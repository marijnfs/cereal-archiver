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


using namespace std;

typedef vector<uint8_t> Bytes;
typedef unique_ptr<Bytes> PBytes;

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

char *DBNAME = "archiver.db";


enum Overwrite {
  OVERWRITE = 0,
  NOOVERWRITE = 1
};

struct DB {
  DB() {
    std::cerr << "opening" << std::endl;
    c(mdb_env_create(&env));
    c(mdb_env_set_mapsize(env, size_t(1) << 40)); // One TB
    //c(mdb_env_open(env, DBNAME, MDB_NOSUBDIR, 0664));
    c(mdb_env_open(env, DBNAME, MDB_NOSUBDIR | MDB_WRITEMAP | MDB_MAPASYNC, 0664));
    
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
    return put(reinterpret_cast<uint8_t *>(&key[0]),
        reinterpret_cast<uint8_t *>(&data[0]), key.size(),
        data.size(), overwrite);
  }

  //classic byte pointer put function
  bool put(uint8_t *key, uint8_t *data, uint64_t key_len, uint64_t data_len, Overwrite overwrite = OVERWRITE) {
    std::cerr << key_len << " " << data_len << std::endl;
    MDB_val mkey{key_len, key}, mdata{data_len, data};

    c(mdb_txn_begin(env, NULL, 0, &txn));
    int result = mdb_put(txn, dbi, &mkey, &mdata, (overwrite == NOOVERWRITE) ? MDB_NOOVERWRITE : 0);
    if (result == MDB_KEYEXIST)
      return false;
    c(result);
    c(mdb_txn_commit(txn));

    return true;
  }

  PBytes get(uint8_t *ptr, uint64_t len) {
    MDB_val mkey{len, ptr};
    MDB_val mdata;
    c(mdb_txn_begin(env, NULL, 0, &txn));
    int result = mdb_get(txn, dbi, &mkey, &mdata);
    if (result == MDB_NOTFOUND)
      return nullptr;
    auto ret_val = make_unique<Bytes>(reinterpret_cast<uint8_t *>(mdata.mv_data),
                             reinterpret_cast<uint8_t *>(mdata.mv_data) +
                                            mdata.mv_size); 
    c(mdb_txn_commit(txn));
    return ret_val;
  }

  PBytes get(std::vector<uint8_t> &key) {
    return get(&key[0], key.size());
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
  PBytes store(T &data) {
    ostringstream oss;
    {
      cereal::PortableBinaryOutputArchive ar(oss);
      ar(data);
	}
    data = make_unique<Bytes>(oss.str().begin(), oss.str().end());
    auto key = get_hash(*data);
    put(*key, *data);
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
    return move(value);
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
    MultiPart
};

struct Entry {
  string name;
  uint64_t size;
  Bytes hash;
  EntryType type;

  template <class Archive>
  void serialize( Archive & ar ) {
    ar(name, size, hash, type);
  }  
};

struct MultiFile {
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

PBytes get_hash(uint8_t *data, uint64_t len) {
  auto hash = make_unique<Bytes>(HASH_BYTES);
  if (blake2b(hash->data(), data, blakekey, HASH_BYTES, len, BLAKE2B_KEYBYTES) < 0)
    throw StringException("hash problem");
  return hash;
}

PBytes get_hash(Bytes &bytes) {
  return get_hash((uint8_t*)bytes.data(), bytes.size());
}


string timestring(uint64_t timestamp) {
 std::tm * ptm = std::localtime((time_t*)&timestamp);
 char buffer[32];
 // Format: Mo, 15.06.2009 20:20:00
 std::strftime(buffer, 32, "%a, %d.%m.%Y %H:%M:%S", ptm); 
 return string(buffer, 32);
}

DB db;

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

    //skip special files, like sockets
    if (file_type == G_FILE_TYPE_SPECIAL) {
      cerr << "SKIPPING SPECIAL FILE: " << base_name << endl;
      continue;
    }
    
    //skip database file
    if (string("archiver.db") == base_name) {
      cerr << "SKIPPING DATABASE FILE: " << base_name << endl;
      continue;
    }
    
    //handle directories by recursively calling enumerate, which returns a hash and total size
    if (file_type == G_FILE_TYPE_DIRECTORY) {
      auto [hash, n] = enumerate(root, child);
      dir.entries.push_back(Entry{base_name, n, *hash, Directory});
      total_size += n;
    } else { //It's a normal file, depending on size store it as one blob or multipart     
      goffset filesize = g_file_info_get_size(finfo);
      cerr << filesize << " " << relative_path << endl;

      if (MAX_FILESIZE && filesize > MAX_FILESIZE) { //on first pass ignore huge files
        cerr << "skipping: " << relative_path << " " << filesize << endl;
        continue;
      }
      
      if (filesize < MULTIPART_SIZE) {
        gchar *data = 0;
        gsize len(0);
        if (!g_file_get_contents(g_file_get_path(child), &data, &len, &error)) {
          cerr << "Read Error: " << g_file_get_path(child) << endl;
          continue;
        }
        cerr << "len: " << len << endl;
        auto hash = get_hash((uint8_t*)data, len);
        db.put(hash->data(), (uint8_t*)data, hash->size(), len, NOOVERWRITE);
      } else { //Too big for direct storage, Multipart file
      }
    }   
  }
}

void backup(GFile *path, string backup_name, string backup_description) {
  
}

PBytes get_root_hash() {
  string root_str("ROOT");
  auto root_hash = db.get((uint8_t*)&root_str[0], root_str.size());
  return move(root_hash);
}

int main(int argc, char **argv) {
  init_blakekey();
  
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
  } else {
    
  }
  
}
