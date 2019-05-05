#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

#include <lmdb.h>
#include <cereal/archives/binary.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/memory.hpp>
#include <blake2.h>

#include <glib-2.0/gio/gio.h>
#include <glib.h>


#include "bytes.h"

using namespace std;

uint HASH_BYTES(32);
uint64_t MAX_FILESIZE(0);
uint64_t MULTIPART_SIZE(uint64_t(2) << 30);
uint8_t blakekey[BLAKE2B_KEYBYTES];

void init_blakekey() {
  for (size_t i = 0; i < BLAKE2B_KEYBYTES; ++i)
    blakekey[i] = (uint8_t)i;
}


struct StringException : public std::exception {
  std::string str;
  StringException(std::string msg_) : str(msg_) {}

  const char *what() const noexcept { return str.c_str(); }
};

std::string user_readable_size(uint64_t size_) {
  double size(size_);
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(2);
  for (auto str : std::vector<std::string>{"B", "KB", "MB", "GB", "TB"}) {
    if (size < 1024.) {
      oss << size << str;
      return oss.str();
    }
    size /= 1024;
  }
  oss << size << "TB";
  return oss.str();
}

string DBNAME = "archiver.db";

PBytes get_hash(uint8_t *data, uint64_t len) {
  auto hash = make_unique<Bytes>(HASH_BYTES);
  if (blake2b(hash->data(), data, blakekey, HASH_BYTES, len, BLAKE2B_KEYBYTES) < 0)
    throw StringException("hash problem");
  return move(hash);
}

PBytes get_hash(Bytes &bytes) {
  return get_hash((uint8_t*)bytes.data(), bytes.size());
}

enum Overwrite {
  OVERWRITE = 0,
  NOOVERWRITE = 1
};

struct DB {
  DB(string db_path, bool read_only = false) {
    std::cerr << "opening database: " << db_path << std::endl;
    c(mdb_env_create(&env));
    c(mdb_env_set_mapsize(env, size_t(1) << 28)); // One TB
    //c(mdb_env_open(env, DBNAME, MDB_NOSUBDIR, 0664));
    c(mdb_env_open(env, db_path.c_str(), (!read_only ? (MDB_NOSUBDIR | MDB_WRITEMAP | MDB_MAPASYNC) : (MDB_NOSUBDIR | MDB_RDONLY)), !read_only ? 0664 : 0444));
    
    c(mdb_txn_begin(env, NULL, 0, &txn));
    c(mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi));
    // char *bla = " ";
    // MDB_val mkey{1, bla}, mdata{1, bla};
    // c( mdb_put(txn, *dbi, &mkey, &mdata, 0) );
    c(mdb_txn_commit(txn));
    // cout << "done" << endl;
  }

  ~DB() { 
    mdb_env_sync(env, 1);
    mdb_dbi_close(env, dbi); 
  }

  //put function for vector types
  bool put(Bytes &key, Bytes &data, Overwrite overwrite) {
    return put(key.data(), data.data(), 
              key.size(), data.size(), overwrite);
  }

  //classic byte pointer put function
  bool put(uint8_t *key, uint8_t *data, uint64_t key_len, uint64_t data_len, Overwrite overwrite) {
    std::cerr << key_len << " " << data_len << std::endl;
    MDB_val mkey{key_len, key}, mdata{data_len, data};

    c(mdb_txn_begin(env, NULL, 0, &txn));
    int result = mdb_put(txn, dbi, &mkey, &mdata, (overwrite == NOOVERWRITE) ? MDB_NOOVERWRITE : 0);
    if (result == MDB_KEYEXIST) {
      c(mdb_txn_commit(txn));
      return false;
    }
    c(result);
    c(mdb_txn_commit(txn));

    return true;
  }

  PBytes get(uint8_t *ptr, uint64_t len) {
    MDB_val mkey{len, ptr};
    MDB_val mdata;
    c(mdb_txn_begin(env, NULL, 0, &txn));
    int result = mdb_get(txn, dbi, &mkey, &mdata);
    if (result == MDB_NOTFOUND) {
      c(mdb_txn_commit(txn));
      return nullptr;
    }
    auto ret_val = make_unique<Bytes>(reinterpret_cast<uint8_t *>(mdata.mv_data),
                             reinterpret_cast<uint8_t *>(mdata.mv_data) +
                                            mdata.mv_size);
    c(mdb_txn_commit(txn));
    return ret_val;
  }

  PBytes get(std::vector<uint8_t> &key) {
    return get(key.data(), key.size());
  }

  bool has(std::vector<uint8_t> &key) {
    MDB_val mkey{key.size(), &key[0]};
    MDB_val mdata;
    c(mdb_txn_begin(env, NULL, 0, &txn));
    int result = mdb_get(txn, dbi, &mkey, &mdata);
    c(mdb_txn_commit(txn));
    return result != MDB_NOTFOUND;
  }

  void copy_db(std::string path) {
    c(mdb_env_copy2(env, path.c_str(), MDB_CP_COMPACT));
  }

  void print_stat() {
    MDB_stat stat;
    c(mdb_txn_begin(env, NULL, 0, &txn));
    mdb_stat(txn, dbi, &stat);
    auto db_size = stat.ms_psize * (stat.ms_leaf_pages + stat.ms_branch_pages + stat.ms_overflow_pages);
    std::cout << "size: " << db_size << " " << user_readable_size(db_size) << std::endl;
    
    printf("  Page size: %u\n", stat.ms_psize);
    printf("  Tree depth: %u\n", stat.ms_depth);
    printf("  Branch pages: %zu\n", stat.ms_branch_pages);
    printf("  Leaf pages: %zu\n", stat.ms_leaf_pages);
    printf("  Overflow pages: %zu\n", stat.ms_overflow_pages);
    printf("  Entries: %zu\n", stat.ms_entries);

  }

  template <typename T>
  PBytes store(T &value) {
    ostringstream oss;
    {
      cereal::PortableBinaryOutputArchive ar(oss);
      ar(value);
      oss.flush();
  	}
    auto contiguous_buf = oss.str();
    auto data = make_unique<Bytes>(contiguous_buf.begin(), contiguous_buf.end());
    auto key = get_hash(*data);
    put(*key, *data, NOOVERWRITE);
    return move(key);
  }

  template <typename T>
  unique_ptr<T> load(Bytes &key) {
    auto data = get(key);
    if (!data)
      return nullptr;
    auto value = make_unique<T>();
    {
      std::string buf((uint8_t*)data->data(), (uint8_t*)data->data() + data->size());	
      istringstream iss(buf);
      cereal::PortableBinaryInputArchive ar(iss);
      ar(*value);
    }
    return value;
  }

  void iterate_all(function<void(Bytes &, Bytes&)> func) {
    MDB_cursor *cursor;
    mdb_txn_begin(env, NULL, 0, &txn);
    c(mdb_cursor_open(txn, dbi, &cursor));

    MDB_val key, value;

    c(mdb_cursor_get(cursor, &key, &value, MDB_FIRST));

    while (true) {
      Bytes bkey(reinterpret_cast<uint8_t *>(key.mv_data),
                             reinterpret_cast<uint8_t *>(key.mv_data) +
                                            key.mv_size);
      Bytes bvalue(reinterpret_cast<uint8_t *>(value.mv_data),
                             reinterpret_cast<uint8_t *>(value.mv_data) +
                                            value.mv_size);
      func(bkey, bvalue);
      if (mdb_cursor_get(cursor, &key, &value, MDB_NEXT))
        break;
    }
    
    mdb_txn_commit(txn);
    mdb_cursor_close(cursor);
  }

  void check_all() {
    MDB_cursor *cursor;
    mdb_txn_begin(env, NULL, 0, &txn);
    c(mdb_cursor_open(txn, dbi, &cursor));

    MDB_val key, value;

    c(mdb_cursor_get(cursor, &key, &value, MDB_FIRST));

    while (true) {
      Bytes bkey(reinterpret_cast<uint8_t *>(key.mv_data),
                             reinterpret_cast<uint8_t *>(key.mv_data) +
                                            key.mv_size);
      Bytes bvalue(reinterpret_cast<uint8_t *>(value.mv_data),
                             reinterpret_cast<uint8_t *>(value.mv_data) +
                                            value.mv_size);
      auto hash = get_hash((uint8_t*)value.mv_data, value.mv_size);
      if (*hash != bkey)
        println("nonmatch for: ", bkey);
      // println("b: ", bkey);
      // println(bkey, " == ", *hash);
      if (mdb_cursor_get(cursor, &key, &value, MDB_NEXT))
        break;
    }
    
    mdb_txn_commit(txn);
    mdb_cursor_close(cursor);
  }

  int rc;
  MDB_env *env = 0;
  MDB_dbi dbi;
  MDB_txn *txn = 0;

  //check function
  void c(int rc) {
    if (rc != 0) {
      fprintf(stderr, "txn->commit: (%d) %s\n", rc, mdb_strerror(rc));
      throw StringException("db error");
    }
  }
};

enum EntryType {
    File,
    Directory,
    Multi
};

struct Entry {
  string name;
  Bytes hash;
  EntryType type;
  uint64_t size = 0;
  uint64_t timestamp = 0;
  bool active = false;

  template <class Archive>
  void serialize( Archive & ar ) {
    ar(name, size, hash, type);
  }  
};

struct MultiPart {
  vector<Bytes> hashes;
  
  template <class Archive>
  void serialize( Archive & ar ) {
    ar(hashes);
  }  
};

struct Dir {
  vector<Entry> entries;
  uint64_t size;

  template <class Archive>
  void serialize( Archive & ar ) {
    ar(entries, size);
  }
};

struct Root {
  vector<Bytes> backups;
  Bytes last_root;
  uint64_t timestamp;

  template <class Archive>
  void serialize( Archive & ar ) {
    ar(backups, last_root, timestamp);
  }
};

struct Backup {
  string name;
  string description;
  uint64_t size;
  Bytes hash;
  uint64_t timestamp;

  template <class Archive>
  void serialize( Archive & ar ) {
    ar(name, description, size, hash, timestamp);
  }
};


string timestring(uint64_t timestamp) {
 std::tm * ptm = std::localtime((time_t*)&timestamp);
 char buffer[64];
 // Format: Mo, 15.06.2009 20:20:00
 size_t len = std::strftime(buffer, 64, "%a, %d.%m.%Y %H:%M:%S", ptm); 
 return string(buffer, len);
}

unique_ptr<DB> db;

tuple<PBytes, uint64_t> enumerate(GFile *root, GFile *path) {
  GFileEnumerator *enumerator;
  GError *error = NULL;
  
  enumerator = g_file_enumerate_children(
                                         path, "*", G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
  if (error != NULL) {
    cerr << error->message << endl;
    return tuple<PBytes, uint64_t>(PBytes(), 0);
  }

  Dir dir;
  uint64_t total_size(0);
  
  while (TRUE) {
    GFile *child;
    GFileInfo *finfo;
    char *relative_path;
    char *base_name;
    
    //grab next file
    if (!g_file_enumerator_iterate(enumerator, &finfo, &child, NULL, &error))
      break;
    if (!finfo)
      break;

    //get it's name, path and type
    base_name = g_file_get_basename(child);
    relative_path = g_file_get_relative_path(root, child);
    auto file_type = g_file_info_get_file_type(finfo);
    auto full_path = g_file_get_path(child);
    GTimeVal gtime;
    g_file_info_get_modification_time (finfo, &gtime);
    uint64_t timestamp = gtime.tv_sec;

    //skip special files, like sockets
    if (file_type == G_FILE_TYPE_SPECIAL) {
      cerr << "SKIPPING SPECIAL FILE: " << base_name << endl;
      continue;
    }
    
    //skip database file
    if (DBNAME == base_name || (DBNAME + "-lock") == base_name) {
      cerr << "SKIPPING DATABASE FILE: " << base_name << endl;
      continue;
    }
    
    //handle directories by recursively calling enumerate, which returns a hash and total size
    if (file_type == G_FILE_TYPE_DIRECTORY) {
      auto [hash, n] = enumerate(root, child);
      dir.entries.push_back(Entry{base_name, *hash, Directory, n, timestamp, true});
      total_size += n;
    } else { 
      //It's a normal file, depending on size store it as one blob or multipart     
      goffset filesize = g_file_info_get_size(finfo);
      cerr << filesize << " " << relative_path << endl;

      if (MAX_FILESIZE && filesize > MAX_FILESIZE) { //on first pass ignore huge files
        cerr << "skipping: " << relative_path << " " << filesize << endl;
        continue;
      }
      
      if (filesize < MULTIPART_SIZE) {
        //File small enough, store diretly
        gchar *data = 0;
        gsize len(0);
        if (!g_file_get_contents(full_path, &data, &len, &error)) {
          cerr << "Read Error: " << full_path << endl;
          continue;
        }
        cerr << "len: " << len << endl;
        auto hash = get_hash((uint8_t*)data, len);

        db->put(hash->data(), (uint8_t*)data, hash->size(), len, NOOVERWRITE);
        dir.entries.push_back(Entry{base_name, *hash, File, len, timestamp, true});
        total_size += len;
      } else {
        //Too big for direct storage, Multipart file
        vector<uint8_t> data(MULTIPART_SIZE);
        auto input_stream = g_file_read (child, NULL, &error);
        if (error != NULL)
          throw StringException(error->message);
        
        MultiPart multipart;
        gsize len(0);
        while (true) {
          gsize bytes_read = g_input_stream_read(G_INPUT_STREAM(input_stream),
                                               (void*)&data[0],
                                               MULTIPART_SIZE,
                                               NULL,
                                               &error);
          if (error != NULL)
            throw StringException(error->message);
          
          if (bytes_read == 0)
            break;
          len += bytes_read;
          
          auto hash = get_hash((uint8_t*)&data[0], bytes_read);
          multipart.hashes.push_back(*hash);
          
          db->put(hash->data(), (uint8_t*)&data[0], hash->size(), bytes_read, NOOVERWRITE); //store part in database
        }
        auto hash = db->store(multipart);
        dir.entries.push_back(Entry{base_name, *hash, Multi, len, timestamp, true});
        total_size += len;
      }
    }
    g_assert(relative_path != NULL);
    g_free(relative_path);
    g_free(base_name);
    g_free(full_path);
  }
  g_object_unref(enumerator);

  //now store the dir
  auto hash = db->store(dir);
  return tuple<PBytes, uint64_t>(move(hash), total_size);
}

PBytes get_root_hash(DB &db) {
  string root_str("ROOT");
  auto root_hash = db.get((uint8_t*)&root_str[0], root_str.size());
  return move(root_hash);
}

void save_root_hash(DB &db, Bytes hash) {
  string root_str("ROOT");
  db.put((uint8_t*)&root_str[0], hash.data(), root_str.size(), hash.size(), OVERWRITE);
}

void join(string join_path) {
  auto other_db = make_unique<DB>(join_path, false);

  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);

  auto other_root_hash = get_root_hash(*other_db);
  auto other_root = other_db->load<Root>(*other_root_hash);

  for (auto other_backup_hash : other_root->backups) {
    bool add(true);
    for (auto backup_hash : root->backups)
      if (other_backup_hash == backup_hash)
        add = false;
    if (add)
      root->backups.push_back(other_backup_hash);
  }

  auto new_root_hash = db->store(*root);

  other_db->iterate_all([](Bytes &key, Bytes &value) {
    db->put(key, value, NOOVERWRITE);
  });
  save_root_hash(*db, *new_root_hash);
}


void backup(GFile *path, string backup_name, string backup_description) {
  Backup backup{backup_name, backup_description};
  {
    auto [hash, n] = enumerate(path, path);
    backup.hash = *hash;
    backup.size = n;
    backup.timestamp = std::time(0);
  }

  auto backup_hash = db->store(backup);

  Root new_root;
  
  //See if there is already a backup
  auto last_root_hash = get_root_hash(*db);
  if (last_root_hash) {
    auto last_root = db->load<Root>(*last_root_hash);
    new_root.last_root = *last_root_hash;
    new_root.backups = last_root->backups;
  }

  new_root.backups.push_back(*backup_hash);
  new_root.timestamp = std::time(0);
  auto new_root_hash = db->store(new_root);
  save_root_hash(*db, *new_root_hash);
}

void list_backups() {
  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);
  print(timestring(root->timestamp));

  for (auto bhash : root->backups) {
    auto backup = db->load<Backup>(bhash);
    print(backup->name);
  }
}

int main(int argc, char **argv) {
  init_blakekey();
  db = make_unique<DB>(DBNAME);

  if (argc < 2) {
    cerr << "no command given, use: " << argv[0] << " [command] [options]" << endl;
    cerr << "command = [archive, dryrun, duplicate, filelist, list, output, stats]" << endl;
    return -1;
  }
 
  string command(argv[1]);
  if (command == "archive") {
    if (argc < 4) {
      cerr << "usage: " << argv[0] << " " << command << " [name] [path] <description>" << endl;
      return -1;
    }
    string name(argv[2]);
    string description;
    if (argc > 4)
      description = string(argv[4]);

    GFile *file = g_file_new_for_path(argv[3]);
    backup(file, name, description);
  } else if (command == "stat") {
    db->print_stat();
  } else if (command == "list") {
    list_backups();
  } else if (command == "check") {
    db->check_all();
  } else if (command == "join") {
    if (argc < 3) {
      cerr << "usage: " << argv[0] << " " << command << " [path of other archive]" << endl;
      return -1;
    }
    join(argv[2]);
  } else {
    print("No such command");
  }  
}
