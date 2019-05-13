#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <queue>
#include <string>

#include <lmdb.h>
#include <cereal/archives/binary.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/memory.hpp>
#include "blake2.h"

#include <glib-2.0/gio/gio.h>
#include <glib.h>


#include "bytes.h"

uint HASH_BYTES(32);
uint64_t MAX_FILESIZE(0);
uint64_t MULTIPART_SIZE(uint64_t(2) << 30);
uint8_t blakekey[BLAKE2B_KEYBYTES];
uint64_t VERSION(1);
bool old_load(true);

enum class BlobType {
  NONE,
  ROOT,
  BACKUP,
  DIRECTORY,
  ENTRY,
  MULTIPART
};

enum class EntryType {
    SINGLEFILE,
    DIRECTORY,
    MULTIFILE
};

using namespace std;

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
  //Old Blake2b API
  // if (blake2b(hash->data(), data, blakekey, HASH_BYTES, len, BLAKE2B_KEYBYTES) < 0)
  if (blake2b(hash->data(), HASH_BYTES, data, len, blakekey, BLAKE2B_KEYBYTES) < 0)
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
    //c(mdb_env_set_mapsize(env, size_t(1) << 28)); // One TB
    c(mdb_env_set_mapsize(env, size_t(840) << 30)); // One TB
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
    if (read_only)
      throw StringException("Not allowed to store, Read Only!");

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
    c(result);

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
    if (read_only)
      throw StringException("Not allowed to store, Read Only!");
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
    mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    c(mdb_cursor_open(txn, dbi, &cursor));

    MDB_val key, value;

    c(mdb_cursor_get(cursor, &key, &value, MDB_FIRST));

    int counter(0);
    while (true) {
      if (counter++ % 1000 == 0)
        print(counter);
      Bytes bkey(reinterpret_cast<uint8_t *>(key.mv_data),
                             reinterpret_cast<uint8_t *>(key.mv_data) +
                                            key.mv_size);
      Bytes bvalue(reinterpret_cast<uint8_t *>(value.mv_data),
                             reinterpret_cast<uint8_t *>(value.mv_data) +
                                            value.mv_size);
      auto hash = get_hash((uint8_t*)value.mv_data, value.mv_size);
      if (*hash != bkey)
        println("nonmatch for a key of len: ", key.mv_size);
      // println("b: ", bkey);
      // println(bkey, " == ", *hash);
      if (mdb_cursor_get(cursor, &key, &value, MDB_NEXT))
        break;
    }
    
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
  }

  int rc;
  MDB_env *env = 0;
  MDB_dbi dbi;
  MDB_txn *txn = 0;
  bool read_only = false;

  //check function
  void c(int rc) {
    if (rc != 0) {
      fprintf(stderr, "txn->commit: (%d) %s\n", rc, mdb_strerror(rc));
      throw StringException("db error");
    }
  }
};


struct Entry {
  uint64_t version = VERSION;

  string name;
  Bytes hash;
  EntryType type;
  uint64_t size = 0;
  uint64_t timestamp = 0;
  uint64_t access = 0;
  bool active = true;
  string content_type;

  template <class Archive>
  void load( Archive & ar ) {
    if (old_load)
      ar(name, hash, type, size, timestamp, access, active);
    else {
      //new load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::ENTRY)
        throw StringException("decerealisation: Not an Entry type");
      int64_t type64(0);
      ar(version, name, hash, type64, size, timestamp, access, active, content_type);
      type = EntryType(type64);
    }
  }  

  template <class Archive>
  void save( Archive & ar ) const {
      // ar(name, hash, type, size, timestamp, access, active);
    
    ar(int64_t(BlobType::ENTRY), version, name, hash, int64_t(type), size, timestamp, access, active, content_type);
  }  
};

struct MultiPart {
  uint64_t version = VERSION;
  vector<Bytes> hashes;
  
  template <class Archive>
  void load( Archive & ar ) {
    if (old_load)
      ar(hashes);
    else {
      //New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::MULTIPART)
        throw StringException("decerealisation: Not a MultiPart type");
      ar(version, hashes);
    }
  }  

  template <class Archive>
  void save( Archive & ar ) const {
    // ar(hashes);

    ar(int64_t(BlobType::MULTIPART), version, hashes);
  }  
};

struct Dir {
  uint64_t version = VERSION;
  vector<Entry> entries;

  template <class Archive>
  void load( Archive & ar ) {
    if (old_load)
      ar(entries);
    else {
      //New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::DIRECTORY)
        throw StringException("decerealisation: Not an Dir type");
      ar(version, entries);
    }
  }

  template <class Archive>
  void save( Archive & ar ) const {
    // ar(entries);

    ar(int64_t(BlobType::DIRECTORY), version, entries);
  }
};

struct Root {
  uint64_t version = VERSION;
  vector<Bytes> backups;
  Bytes last_root;
  uint64_t timestamp;

  template <class Archive>
  void load( Archive & ar ) {
    if (old_load)
      ar(backups, last_root, timestamp);
    else {
      //New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::ROOT)
        throw StringException("decerealisation: Not an Root type");
      ar(version, backups, last_root, timestamp);
    }
  }

  template <class Archive>
  void save( Archive & ar ) const {
    // ar(backups, last_root, timestamp);

    ar(int64_t(BlobType::ROOT), version, backups, last_root, timestamp);
  }
};

struct Backup {
  uint64_t version = VERSION;
  string name;
  string description;
  uint64_t size;

  //temporarily it will have both
  Bytes entry_hash;
  Entry entry; 

  uint64_t timestamp;

  template <class Archive>
  void load( Archive & ar ) {
    if (old_load)
      ar(name, description, size, entry_hash, timestamp);
    else {
      //New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::BACKUP)
        throw StringException("decerealisation: Not an Backup type");
      ar(version, name, description, size, entry, timestamp);
    }
  }

  template <class Archive>
  void save( Archive & ar ) const {
    // ar(name, description, size, entry_hash, timestamp);
  
    ar(int64_t(BlobType::BACKUP), version, name, description, size, entry, timestamp);
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

Entry enumerate(GFile *root, GFile *path) {
  GFileEnumerator *enumerator;
  GError *error = NULL;

  enumerator = g_file_enumerate_children(
                                         path, "*", G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
  if (error != NULL) {
    cerr << error->message << endl;
    return Entry{};
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
      auto entry = enumerate(root, child);
      dir.entries.push_back(entry);
      total_size += entry.size;
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

        uint64_t access = 0;
        bool active = true;
        string content_type;

        dir.entries.push_back(Entry{VERSION, base_name, *hash, EntryType::SINGLEFILE, len, timestamp, access, active, content_type});
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
        uint64_t access = 0;
        bool active = true;
        string content_type;

        dir.entries.push_back(Entry{VERSION, base_name, *hash, EntryType::MULTIFILE, len, timestamp, access, active, content_type});

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

  //get the dir timestamp
  uint64_t timestamp = 0;
  char *base_name_c = g_file_get_basename(path);
  string base_name(base_name_c);
  g_free(base_name_c);

  uint64_t access = 0;
  bool active = true;
  string content_type;

  Entry dir_entry{VERSION, base_name, *hash, EntryType::DIRECTORY, total_size, timestamp, access, active, content_type};
  return dir_entry;
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

void output_file(string path, string target_path) {
  //extract the backup part
  auto backup_sep = path.find(":");
  if (backup_sep == string::npos) {
    print("need a backup seperator [backup:path]");
    return;
  }
  auto backup_name = path.substr(0, backup_sep);
  path = path.substr(backup_sep+1);

  //remove initial slash
  auto first_slash = path.find("/");
  if (first_slash == string::npos || first_slash != 0) {
    print("path after backup should start with / (slash)");
    return;
  }
  path = path.substr(first_slash + 1);

  //loop over backups
  
  auto root = db->load<Root>(*get_root_hash(*db));
  for (auto b : root->backups) {
    auto backup = db->load<Backup>(b);
    if (backup->name != backup_name)
      continue;
    string search_path = path;

    unique_ptr<Dir> dir;
    if (old_load) {
      auto start_entry = db->load<Entry>(backup->entry_hash);
      dir = db->load<Dir>(start_entry->hash);
    } else {
      dir = db->load<Dir>(backup->entry.hash);
    }

    bool go = true;
    while (go && search_path.size()) {
      go = false;
      string current_search = search_path;
      auto slash = search_path.find("/");
      if (slash != string::npos)
        current_search = current_search.substr(0, slash);
      for (auto entry : dir->entries) {
        if (current_search == entry.name) {
          if (entry.type != EntryType::DIRECTORY) {
            ofstream outfile(target_path);
            
            if (entry.type == EntryType::SINGLEFILE) {
              auto data = db->get(entry.hash);
              print("found file: ", entry.name);
              outfile.write((char*)data->data(), data->size());

            } else if (entry.type == EntryType::SINGLEFILE) {
              auto multi = db->load<MultiPart>(entry.hash);
              for (auto h : multi->hashes) {
                auto data = db->get(h);
                outfile.write((char*)data->data(), data->size());
              }
            }
            throw StringException("Found File");
          } else {
            if (entry.name >= search_path)
              throw StringException("problem with path");
            go = true;
            search_path = search_path.substr(current_search.size() + 1);
            dir = db->load<Dir>(entry.hash);
          }
        }
      }
    }

  }
}

void backup(GFile *path, string backup_name, string backup_description) {
  Backup backup{VERSION, backup_name, backup_description};
  {
    auto entry = enumerate(path, path);
    auto entry_hash = db->store(entry);
    backup.entry_hash = *entry_hash;
    backup.size = entry.size;
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

void list_all_files() {
  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);
  print(timestring(root->timestamp));

  for (auto bhash : root->backups) {
    auto backup = db->load<Backup>(bhash);
    auto backup_name = backup->name;

    unique_ptr<Dir> root_dir;

    if (old_load) {
      ///Old loading
      auto root_entry = db->load<Entry>(backup->entry_hash);
      root_dir = db->load<Dir>(root_entry->hash);
    } else {
      //New loading
      auto root_entry = backup->entry;
      root_dir = db->load<Dir>(root_entry.hash);
    }

    cout << "backup " << backup_name << endl;
    cout << root_dir->entries.size() << endl;
    queue<unique_ptr<Dir>> q;
    queue<string> name_q;

    q.push(move(root_dir));
    name_q.push(backup_name + ":");

    while (!q.empty()) {
      auto cur_dir = move(q.front());
      auto cur_name = name_q.front();
      q.pop();
      name_q.pop();

      for (auto entry : cur_dir->entries) {
        if (entry.type != EntryType::DIRECTORY)
          println(user_readable_size(entry.size), " ", cur_name + "/" + entry.name);
        else {
          q.push(move(db->load<Dir>(entry.hash)));
          name_q.push(cur_name + "/" + entry.name);
        }
      }
        
    }
    print(backup->name);
  }
}

unique_ptr<Entry> convert_entry(DB &target_db, Entry &entry) {
  print("convert ", entry.name);
  auto new_entry = make_unique<Entry>(entry);
  if (entry.hash.empty()) {
    print("hash empty");
    new_entry->active = false;
    return new_entry;
  }
  if (entry.type == EntryType::DIRECTORY) {
    auto dir = db->load<Dir>(entry.hash);
    auto new_dir = make_unique<Dir>();
    for (auto dir_entry : dir->entries) {
      auto conv_entry = convert_entry(target_db, dir_entry);
      new_dir->entries.push_back(*conv_entry);
    }
    auto dir_hash = target_db.store(*new_dir);
    new_entry->hash = *dir_hash;
  }
  if (entry.type == EntryType::SINGLEFILE) {
    auto data = db->get(entry.hash);
    target_db.put(entry.hash, *data, NOOVERWRITE);    
  }
  if (entry.type == EntryType::MULTIFILE) {
    auto multi = db->load<MultiPart>(entry.hash);
    for (auto h : multi->hashes) {
      auto data = db->get(h);
      target_db.put(h, *data, NOOVERWRITE);   
    }
    auto multi_hash = target_db.store(*multi);
    new_entry->hash = *multi_hash;
  }
  return new_entry;
}

void move_to(string target_db_path) {
  db->read_only = true;
  auto target_db = make_unique<DB>(target_db_path);

  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);

  Root new_root;
  new_root.version = 1;
  new_root.timestamp = root->timestamp;
  new_root.last_root = *root_hash;


  for (auto bhash : root->backups) {
    auto backup = db->load<Backup>(bhash);

    //conversion of old setup
    auto backup_entry = db->load<Entry>(backup->entry_hash);

    backup_entry = convert_entry(*target_db, *backup_entry);
    backup->entry = *backup_entry;
    auto backup_hash = target_db->store(*backup);
    new_root.backups.push_back(*backup_hash);
  }
  
  auto new_root_hash = target_db->store(new_root);
  save_root_hash(*target_db, *new_root_hash);
}


int main(int argc, char **argv) {
  cout << "Cereal Archiver" << endl;
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
  } else if (command == "filelist") {
    list_all_files();
  } else if (command == "check") {
    db->check_all();
  } else if (command == "moveto") {
    if (argc < 3) {
      cerr << "usage: " << argv[0] << " " << command << " [path of other archive]" << endl;
      return -1;
    }
    move_to(argv[2]);
  } else if (command == "file") {
    if (argc < 4) {
      cerr << "usage: " << argv[0] << " " << command << " [backup:filepath] [target path]" << endl;
      return -1;
    }
    output_file(argv[2], argv[3]);
  } else if (command == "join") {
    if (argc < 3) {
      cerr << "usage: " << argv[0] << " " << command << " [path of other archive]" << endl;
      return -1;
    }
    join(argv[2]);
  } else {
    print("No such command: ", command);
  }  
}
