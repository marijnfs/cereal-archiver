#include <fstream>
#include <iomanip>
#include <iostream>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

#include <lmdb.h>
#include <cereal/archives/binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>

// #include <rocksdb/db.h>
// #include <rocksdb/slice.h>
// #include <rocksdb/options.h>

#include "blake2.h"

#include <glib-2.0/gio/gio.h>
#include <glib.h>

#include "args.hxx"
#include "bytes.h"
#include "server/mime_types.hpp"
#include "server/server.hpp"

uint HASH_BYTES(32);
uint64_t MAX_FILESIZE(0);
uint64_t MULTIPART_SIZE(uint64_t(2) << 30);
uint8_t blakekey[BLAKE2B_KEYBYTES];
uint64_t VERSION(1);
bool old_load(false);

enum class ReadOnly { No = 0, Yes = 1 };

enum class BlobType { NONE, ROOT, BACKUP, DIRECTORY, ENTRY, MULTIPART };

enum class EntryType { SINGLEFILE, DIRECTORY, MULTIFILE };

using namespace std;

void init_blakekey() {
  for (size_t i = 0; i < BLAKE2B_KEYBYTES; ++i)
    blakekey[i] = (uint8_t)i;
}

struct StringException : public std::exception {
  std::string str;
  StringException(std::string msg_) : str(msg_) {}

  const char* what() const noexcept { return str.c_str(); }
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

PBytes get_hash(uint8_t* data, uint64_t len) {
  auto hash = make_unique<Bytes>(HASH_BYTES);
  // Old Blake2b API
  // if (blake2b(hash->data(), data, blakekey, HASH_BYTES, len,
  // BLAKE2B_KEYBYTES) < 0)
  if (blake2b(hash->data(), HASH_BYTES, data, len, blakekey, BLAKE2B_KEYBYTES) <
      0)
    throw StringException("hash problem");
  return move(hash);
}

PBytes get_hash(Bytes& bytes) {
  return get_hash((uint8_t*)bytes.data(), bytes.size());
}

enum Overwrite { OVERWRITE = 0, NOOVERWRITE = 1 };

struct DB {
  DB(string db_path_, ReadOnly read_only_ = ReadOnly::Yes)
      : db_path(db_path_), read_only(read_only_) {}

  bool put(Bytes& data) {
    auto hash = get_hash(data);
    return put(*hash, data, NOOVERWRITE);
  }

  // put function for vector types
  bool put(Bytes& key, Bytes& data, Overwrite overwrite) {
    return put(key.data(), data.data(), key.size(), data.size(), overwrite);
  }

  PBytes get(std::vector<uint8_t>& key) { return get(key.data(), key.size()); }

  template <typename T>
  PBytes store(T& value) {
    if (read_only == ReadOnly::Yes)
      throw StringException("Not allowed to store, Read Only!");
    ostringstream oss;
    {
      cereal::PortableBinaryOutputArchive ar(oss);
      ar(value);
      oss.flush();
    }
    auto contiguous_buf = oss.str();
    auto data =
        make_unique<Bytes>(contiguous_buf.begin(), contiguous_buf.end());
    auto key = get_hash(*data);
    this->put(*key, *data, NOOVERWRITE);
    return move(key);
  }

  template <typename T>
  unique_ptr<T> load(Bytes& key) {
    auto data = get(key);
    if (!data)
      return nullptr;
    auto value = make_unique<T>();
    {
      std::string buf((uint8_t*)data->data(),
                      (uint8_t*)data->data() + data->size());
      istringstream iss(buf);
      cereal::PortableBinaryInputArchive ar(iss);
      ar(*value);
    }
    return value;
  }

  virtual ~DB() {}

  // classic byte pointer put function
  virtual bool put(uint8_t* key,
                   uint8_t* data,
                   uint64_t key_len,
                   uint64_t data_len,
                   Overwrite overwrite) {
    throw std::runtime_error("Not implemented");
  }

  virtual PBytes get(uint8_t* ptr, uint64_t len) {
    throw std::runtime_error("Not implemented");
  }

  virtual bool has(std::vector<uint8_t>& key) {
    throw std::runtime_error("Not implemented");
  }

  virtual void copy_db(std::string path) {
    throw std::runtime_error("Not implemented");
  }

  virtual void print_stat() { throw std::runtime_error("Not implemented"); }

  virtual void check_all() { throw std::runtime_error("Not implemented"); }

  virtual void iterate_all(function<void(Bytes&, Bytes&)> func) {
    throw std::runtime_error("Not implemented");
  }

  string db_path;
  ReadOnly read_only = ReadOnly::Yes;
};

// struct Rocks_DB : public DB {
//   Rocks_DB(string db_path_, ReadOnly read_only_ = ReadOnly::Yes) :
//   DB(db_path_, read_only_) {
//     if (db_path.size() < 8 || db_path.substr(db_path.size() - 8) !=
//     ".rocksdb")
//       throw std::runtime_error("db has wrong name, must end with .rocksdb");
//     rocksdb::Options options;

//     // Optimize RocksDB. This is the easiest way to get RocksDB to perform
//     well options.IncreaseParallelism();
//     options.OptimizeLevelStyleCompaction();
//     options.OptimizeForPointLookup(512 << 20);
//     options.unordered_write = true;
//     options.write_buffer_size = 512 << 20; //512 megabyte
//     //options.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10, true))

//     // create the DB if it's not already present
//     options.create_if_missing = read_only_ == ReadOnly::No;

//     rocksdb::Status s = rocksdb::DB::Open(options, db_path, &db);
//     if (!s.ok()) {
//       cerr << "Couldn't open " << db_path << endl;
//       throw std::runtime_error("Failed to open db: ");
//     }

//     readOptions = rocksdb::ReadOptions();
//     quickReadOptions = rocksdb::ReadOptions();
//     quickReadOptions.verify_checksums = false;

//     writeOptions = rocksdb::WriteOptions();
//   }

//   ~Rocks_DB() {
//     if (db) {
//         db->SyncWAL();
//         auto status = db->Close();
//         if (!status.ok())
//             cerr << "Closing of Rocksdb database failed" << endl;
//         delete db;
//     }
//   }

//   bool put(uint8_t *key, uint8_t *data, uint64_t key_len, uint64_t data_len,
//   Overwrite overwrite) {
//       if (read_only == ReadOnly::Yes )
//           throw std::runtime_error("Not allowed to put values in readonly
//           database");
//       if (overwrite == NOOVERWRITE) {
//           std::string tmp;
//           if (!db->Get(quickReadOptions, rocksdb::Slice((const char *)key,
//           key_len), &tmp).ok()) {
//               print("Skipping insertion");
//               return true;
//           }
//       }
//       auto status = db->Put(writeOptions,
//                           rocksdb::Slice((const char *)key, key_len),
//                           rocksdb::Slice((const char *)data, data_len));
//     if (!status.ok()) {
//       return false;
//     }
//     return true;
//   }

//   PBytes get(uint8_t *ptr, uint64_t len) {
//     std::string data;
//     auto status = db->Get(readOptions, rocksdb::Slice((const char *)ptr,
//     len), &data); if (!status.ok())
//       return nullptr;

//     return make_unique<Bytes>(reinterpret_cast<uint8_t const *>(data.data()),
//                              reinterpret_cast<uint8_t const *>(data.data()) +
//                              data.size());
//   }

//   virtual bool has(std::vector<uint8_t> &key) {
//     auto status = db->Get(readOptions, rocksdb::Slice((const char
//     *)key.data(), key.size()), nullptr); return status.ok();
//   }

//   void iterate_all(function<void(Bytes &, Bytes&)> func) {
//     rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
//     for (it->SeekToFirst(); it->Valid(); it->Next()) {
//       Bytes key_bytes(it->key().data(), it->key().data() + it->key().size());
//       Bytes value_bytes(it->value().data(), it->value().data() +
//       it->value().size()); func(key_bytes, value_bytes);
//     }
//     assert(it->status().ok()); // Check for any errors found during the scan
//     delete it;
//   }

//   rocksdb::DB *db = nullptr;

//   rocksdb::WriteOptions writeOptions;
//   rocksdb::ReadOptions readOptions;
//   rocksdb::ReadOptions quickReadOptions;
// };

struct MDB_DB : public DB {
  MDB_DB(string db_path_, ReadOnly read_only_ = ReadOnly::Yes)
      : DB(db_path_, read_only_) {
    std::cerr << "opening database: " << db_path << std::endl;
    c(mdb_env_create(&env));
    // c(mdb_env_set_mapsize(env, size_t(1) << 28)); // One TB
    c(mdb_env_set_mapsize(env, size_t(840) << 30));  // One TB
    // c(mdb_env_open(env, DBNAME, MDB_NOSUBDIR, 0664));
    c(mdb_env_open(env, db_path.c_str(),
                   (read_only == ReadOnly::No
                        ? (MDB_NOSUBDIR | MDB_WRITEMAP | MDB_MAPASYNC)
                        : (MDB_NOSUBDIR | MDB_RDONLY)),
                   read_only == ReadOnly::No ? 0664 : 0444));
    // c(mdb_env_open(env, db_path.c_str(), (!read_only ? (MDB_NOSUBDIR |
    // MDB_WRITEMAP) : (MDB_NOSUBDIR | MDB_RDONLY)), !read_only ? 0664 : 0444));

    c(mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0,
                    &txn));
    c(mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi));
    c(mdb_txn_commit(txn));
  }

  ~MDB_DB() {
    mdb_env_sync(env, 1);
    mdb_dbi_close(env, dbi);
  }

  // classic byte pointer put function
  bool put(uint8_t* key,
           uint8_t* data,
           uint64_t key_len,
           uint64_t data_len,
           Overwrite overwrite) {
    if (read_only == ReadOnly::Yes)
      throw StringException("Not allowed to store, Read Only!");

    MDB_val mkey{key_len, key}, mdata{data_len, data};

    c(mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0,
                    &txn));
    int result = mdb_put(txn, dbi, &mkey, &mdata,
                         (overwrite == NOOVERWRITE) ? MDB_NOOVERWRITE : 0);
    if (result == MDB_KEYEXIST) {
      c(mdb_txn_commit(txn));
      return false;
    }
    c(result);
    c(mdb_txn_commit(txn));

    return true;
  }

  PBytes get(uint8_t* ptr, uint64_t len) {
    MDB_val mkey{len, ptr};
    MDB_val mdata;
    c(mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0,
                    &txn));
    int result = mdb_get(txn, dbi, &mkey, &mdata);

    if (result == MDB_NOTFOUND) {
      c(mdb_txn_commit(txn));
      return nullptr;
    }
    c(result);

    auto ret_val = make_unique<Bytes>(
        reinterpret_cast<uint8_t*>(mdata.mv_data),
        reinterpret_cast<uint8_t*>(mdata.mv_data) + mdata.mv_size);
    c(mdb_txn_commit(txn));
    return ret_val;
  }

  bool has(std::vector<uint8_t>& key) {
    MDB_val mkey{key.size(), &key[0]};
    MDB_val mdata;
    c(mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0,
                    &txn));
    int result = mdb_get(txn, dbi, &mkey, &mdata);
    c(mdb_txn_commit(txn));
    return result != MDB_NOTFOUND;
  }

  void copy_db(std::string path) {
    c(mdb_env_copy2(env, path.c_str(), MDB_CP_COMPACT));
  }

  void print_stat() {
    MDB_stat stat;
    c(mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0,
                    &txn));
    mdb_stat(txn, dbi, &stat);
    auto db_size = stat.ms_psize * (stat.ms_leaf_pages + stat.ms_branch_pages +
                                    stat.ms_overflow_pages);
    std::cout << "size: " << db_size << " " << user_readable_size(db_size)
              << std::endl;

    printf("  Page size: %u\n", stat.ms_psize);
    printf("  Tree depth: %u\n", stat.ms_depth);
    printf("  Branch pages: %zu\n", stat.ms_branch_pages);
    printf("  Leaf pages: %zu\n", stat.ms_leaf_pages);
    printf("  Overflow pages: %zu\n", stat.ms_overflow_pages);
    printf("  Entries: %zu\n", stat.ms_entries);
  }

  void iterate_all(function<void(Bytes&, Bytes&)> func) {
    MDB_cursor* cursor;
    mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0, &txn);
    c(mdb_cursor_open(txn, dbi, &cursor));

    MDB_val key, value;

    c(mdb_cursor_get(cursor, &key, &value, MDB_FIRST));

    while (true) {
      Bytes bkey(reinterpret_cast<uint8_t*>(key.mv_data),
                 reinterpret_cast<uint8_t*>(key.mv_data) + key.mv_size);
      Bytes bvalue(reinterpret_cast<uint8_t*>(value.mv_data),
                   reinterpret_cast<uint8_t*>(value.mv_data) + value.mv_size);
      func(bkey, bvalue);
      if (mdb_cursor_get(cursor, &key, &value, MDB_NEXT))
        break;
    }

    mdb_txn_commit(txn);
    mdb_cursor_close(cursor);
  }

  void check_all() {
    MDB_cursor* cursor;
    mdb_txn_begin(env, NULL, read_only == ReadOnly::Yes ? MDB_RDONLY : 0, &txn);
    c(mdb_cursor_open(txn, dbi, &cursor));

    MDB_val key, value;

    c(mdb_cursor_get(cursor, &key, &value, MDB_FIRST));

    int counter(0);
    while (true) {
      if (counter++ % 1000 == 0)
        print(counter);
      Bytes bkey(reinterpret_cast<uint8_t*>(key.mv_data),
                 reinterpret_cast<uint8_t*>(key.mv_data) + key.mv_size);
      Bytes bvalue(reinterpret_cast<uint8_t*>(value.mv_data),
                   reinterpret_cast<uint8_t*>(value.mv_data) + value.mv_size);
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
  MDB_env* env = 0;
  MDB_dbi dbi;
  MDB_txn* txn = 0;

  // check function
  void c(int rc) {
    if (rc != 0) {
      fprintf(stderr, "txn->commit: (%d) %s\n", rc, mdb_strerror(rc));
      throw StringException("db error");
    }
  }
};

vector<char> HEX_TABLE = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

struct Dir_DB : public DB {
  Dir_DB(string db_path_, ReadOnly read_only_ = ReadOnly::Yes)
      : DB(db_path_, read_only_) {
    std::cerr << "opening database: " << db_path << std::endl;
    db_gfile = g_file_new_for_path(db_path.c_str());

    print("Checking existence of ", db_path);
    if (!g_file_query_exists(db_gfile, nullptr)) {
      if (read_only == ReadOnly::Yes)
        throw StringException(
            "DB doesn't exist, Can't create new dir in readonly mode");
      if (!g_file_make_directory(db_gfile, nullptr, nullptr))
        throw StringException("Can't create new dir, something blocking");
    }
  }

  // classic byte pointer put function
  virtual bool put(uint8_t* key,
                   uint8_t* data,
                   uint64_t key_len,
                   uint64_t data_len,
                   Overwrite overwrite) {
    if (read_only == ReadOnly::Yes)
      throw StringException("Not allowed to store, Read Only!");

    std::vector<uint8_t> key_vec(key, key + key_len);
    string key_str = to_hex(key_vec);
    auto splitted_key = split_key(key_str);

    // check and create dir path
    auto dir_path = db_path + "/" + splitted_key.first;
    auto dir_gfile = g_file_new_for_path(dir_path.c_str());
    if (!g_file_query_exists(dir_gfile, nullptr))
      if (!g_file_make_directory(dir_gfile, nullptr, nullptr))
        throw StringException("Can't create new dir, something blocking");

    // check value path and see if it exists
    auto value_path = dir_path + "/" + splitted_key.second;
    auto value_gfile = g_file_new_for_path(value_path.c_str());

    if (overwrite == NOOVERWRITE) {
      if (g_file_query_exists(value_gfile, nullptr)) {
        auto file_info =
            g_file_query_info(value_gfile, G_FILE_ATTRIBUTE_STANDARD_SIZE,
                              G_FILE_QUERY_INFO_NONE, nullptr, nullptr);
        auto file_size = g_file_info_get_size(file_info);
        g_object_unref(file_info);

        if (file_size == data_len) {  // if true we assume its written
          print("Skipping file ", key_str);
          g_object_unref(dir_gfile);
          g_object_unref(value_gfile);
          return false;
        }
      }
    }

    ofstream of(value_path, std::ofstream::binary);
    if (!of) {
      cerr << "failed opening " << value_path << " for writing" << endl;
      throw StringException("Output File Creation Failed");
    }

    if (!of.write((char*)data, data_len)) {
      cerr << "failed writing to " << value_path << endl;
      throw StringException("Output File Writing Failed");
    }

    g_object_unref(dir_gfile);
    g_object_unref(value_gfile);
    return true;
  }

  virtual PBytes get(uint8_t* ptr, uint64_t len) {
    std::vector<uint8_t> key(ptr, ptr + len);
    string key_str = to_hex(key);
    auto splitted_key = split_key(key_str);
    auto dir_path = db_path + "/" + splitted_key.first;
    auto value_path = dir_path + "/" + splitted_key.second;

    ifstream in_file(value_path, std::ifstream::binary);

    if (!in_file) {
      print("Couldn't find key");
      return nullptr;
    }

    in_file.seekg(0, in_file.end);
    auto length = in_file.tellg();
    in_file.seekg(0, in_file.beg);

    auto bytes = make_unique<Bytes>(length);

    if (!in_file.read((char*)bytes->data(), bytes->size()))
      throw StringException("Reading failed");

    return bytes;
  }

  virtual bool has(std::vector<uint8_t>& key) {
    std::string key_str = to_hex(key);
    auto splitted_key = split_key(key_str);
    auto dir_path = db_path + "/" + splitted_key.first;
    auto value_path = dir_path + "/" + splitted_key.second;

    GFile* file = g_file_new_for_path(value_path.c_str());
    bool exists = g_file_query_exists(file, nullptr);
    g_object_unref(file);
    return exists;
  }

  virtual void copy_db(std::string path) {
    throw std::runtime_error("Not implemented");
  }

  virtual void print_stat() { throw std::runtime_error("Not implemented"); }

  virtual void check_all() { throw std::runtime_error("Not implemented"); }

  virtual void iterate_all(function<void(Bytes&, Bytes&)> func) {
    throw std::runtime_error("Not implemented");
  }

  std::pair<string, string> split_key(string key) {
    if (key.size() < 2) {
      throw StringException("Key too short");
    }
    return std::pair<string, string>(key.substr(0, 2), key.substr(2));
  }

  string to_hex(std::vector<uint8_t>& key) {
    std::ostringstream stream;
    for (auto& k : key) {
      stream << HEX_TABLE[k / 16];
      stream << HEX_TABLE[k % 16];
    }
    return stream.str();
  }

  GFile* db_gfile = nullptr;
};

std::unique_ptr<DB> load_db(string path, ReadOnly readonly) {
  /// if ends with .rocksdb we assume its rocksdb, otherwise lmdb
  // if (path.size() < 8 || path.substr(path.size() - 8) == ".rocksdb")
  //   return std::make_unique<Rocks_DB>(path, readonly);
  // else
  if (path.size() < 3 || path.substr(path.size() - 3) == ".db")
    return std::make_unique<MDB_DB>(path, readonly);
  else if (path.size() < 6 || path.substr(path.size() - 6) == ".dirdb")
    return std::make_unique<Dir_DB>(path, readonly);
  else
    throw StringException("Failed to load db, no valid path ending");
}

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
  void load(Archive& ar) {
    if (old_load)
      ar(name, hash, type, size, timestamp, access, active);
    else {
      // new load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::ENTRY)
        throw StringException("decerealisation: Not an Entry type");
      int64_t type64(0);
      ar(version, name, hash, type64, size, timestamp, access, active,
         content_type);
      type = EntryType(type64);
    }
  }

  template <class Archive>
  void save(Archive& ar) const {
    // ar(name, hash, type, size, timestamp, access, active);

    ar(int64_t(BlobType::ENTRY), version, name, hash, int64_t(type), size,
       timestamp, access, active, content_type);
  }
};

struct MultiPart {
  uint64_t version = VERSION;
  vector<Bytes> hashes;

  template <class Archive>
  void load(Archive& ar) {
    if (old_load)
      ar(hashes);
    else {
      // New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::MULTIPART)
        throw StringException("decerealisation: Not a MultiPart type");
      ar(version, hashes);
    }
  }

  template <class Archive>
  void save(Archive& ar) const {
    // ar(hashes);

    ar(int64_t(BlobType::MULTIPART), version, hashes);
  }
};

struct Dir {
  uint64_t version = VERSION;
  vector<Entry> entries;

  template <class Archive>
  void load(Archive& ar) {
    if (old_load)
      ar(entries);
    else {
      // New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::DIRECTORY)
        throw StringException("decerealisation: Not an Dir type");
      ar(version, entries);
    }
  }

  template <class Archive>
  void save(Archive& ar) const {
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
  void load(Archive& ar) {
    if (old_load)
      ar(backups, last_root, timestamp);
    else {
      // New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::ROOT) {
        throw StringException("decerealisation: Not an Root type");
      }
      ar(version, backups, last_root, timestamp);
    }
  }

  template <class Archive>
  void save(Archive& ar) const {
    // ar(backups, last_root, timestamp);

    ar(int64_t(BlobType::ROOT), version, backups, last_root, timestamp);
  }
};

struct Backup {
  uint64_t version = VERSION;
  string name;
  string description;
  uint64_t size = 0;

  // temporarily it will have both
  Bytes entry_hash;
  Entry entry;

  uint64_t timestamp = 0;

  template <class Archive>
  void load(Archive& ar) {
    if (old_load)
      ar(name, description, size, entry_hash, timestamp);
    else {
      // New load
      int64_t btype(0);
      ar(btype);
      if (btype != (int64_t)BlobType::BACKUP)
        throw StringException("decerealisation: Not an Backup type");
      ar(version, name, description, size, entry, timestamp);
    }
  }

  template <class Archive>
  void save(Archive& ar) const {
    // ar(name, description, size, entry_hash, timestamp);

    ar(int64_t(BlobType::BACKUP), version, name, description, size, entry,
       timestamp);
  }
};

string timestring(uint64_t timestamp) {
  std::tm* ptm = std::localtime((time_t*)&timestamp);
  char buffer[64];
  // Format: Mo, 15.06.2009 20:20:00
  size_t len = std::strftime(buffer, 64, "%a, %d.%m.%Y %H:%M:%S", ptm);
  return string(buffer, len);
}

unique_ptr<DB> db;

Entry enumerate(GFile* root, GFile* path, bool ignore_hidden = false) {
  GFileEnumerator* enumerator;
  GError* error = NULL;

  enumerator = g_file_enumerate_children(
      path, "*", G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
  if (error != NULL) {
    cerr << error->message << endl;
    return Entry{};
  }

  Dir dir;
  uint64_t total_size(0);

  while (true) {
    GFile* child;
    GFileInfo* finfo;
    char* relative_path;
    char* base_name;

    // grab next file
    if (!g_file_enumerator_iterate(enumerator, &finfo, &child, NULL, &error))
      break;
    if (!finfo)
      break;

    // get it's name, path and type
    base_name = g_file_get_basename(child);
    relative_path = g_file_get_relative_path(root, child);
    auto file_type = g_file_info_get_file_type(finfo);
    auto full_path = g_file_get_path(child);
    char const* content_type = g_file_info_get_content_type(finfo);
    GTimeVal gtime;
    g_file_info_get_modification_time(finfo, &gtime);
    uint64_t timestamp = gtime.tv_sec;

    if (ignore_hidden && relative_path[0] == '.') {
      g_free(relative_path);
      g_free(base_name);
      g_free(full_path);
      continue;
    }
    // skip special files, like sockets
    if (file_type == G_FILE_TYPE_SPECIAL) {
      cerr << "SKIPPING SPECIAL FILE: " << base_name << endl;
      continue;
    }

    // skip database file
    if (DBNAME == base_name || (DBNAME + "-lock") == base_name) {
      cerr << "SKIPPING DATABASE FILE: " << base_name << endl;
      continue;
    }

    // handle directories by recursively calling enumerate, which returns a hash
    // and total size
    if (file_type == G_FILE_TYPE_DIRECTORY) {
      auto entry = enumerate(root, child);
      dir.entries.push_back(entry);
      total_size += entry.size;
    } else {
      // It's a normal file, depending on size store it as one blob or multipart
      goffset filesize = g_file_info_get_size(finfo);
      cerr << filesize << " " << relative_path << endl;

      if (MAX_FILESIZE &&
          filesize > MAX_FILESIZE) {  // on first pass ignore huge files
        cerr << "skipping: " << relative_path << " " << filesize << endl;
        continue;
      }

      if (filesize < MULTIPART_SIZE) {
        // File small enough, store diretly
        gchar* data = 0;
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

        g_free(data);
        dir.entries.push_back(Entry{VERSION, base_name, *hash,
                                    EntryType::SINGLEFILE, len, timestamp,
                                    access, active, content_type});
        total_size += len;
      } else {
        // Too big for direct storage, Multipart file
        vector<uint8_t> data(MULTIPART_SIZE);
        auto input_stream = g_file_read(child, NULL, &error);
        if (error != NULL)
          throw StringException(error->message);

        MultiPart multipart;
        gsize len(0);
        while (true) {
          gsize bytes_read =
              g_input_stream_read(G_INPUT_STREAM(input_stream), (void*)&data[0],
                                  MULTIPART_SIZE, NULL, &error);
          if (error != NULL)
            throw StringException(error->message);

          if (bytes_read == 0)
            break;
          len += bytes_read;

          auto hash = get_hash((uint8_t*)&data[0], bytes_read);
          multipart.hashes.push_back(*hash);

          db->put(hash->data(), (uint8_t*)&data[0], hash->size(), bytes_read,
                  NOOVERWRITE);  // store part in database
        }
        auto hash = db->store(multipart);
        uint64_t access = 0;
        bool active = true;

        dir.entries.push_back(Entry{VERSION, base_name, *hash,
                                    EntryType::MULTIFILE, len, timestamp,
                                    access, active, content_type});

        total_size += len;
      }
    }
    g_assert(relative_path != NULL);
    g_free(relative_path);
    g_free(base_name);
    g_free(full_path);
  }
  g_object_unref(enumerator);

  // now store the dir
  auto hash = db->store(dir);

  // get the dir timestamp
  uint64_t timestamp = 0;
  char* base_name_c = g_file_get_basename(path);
  string base_name(base_name_c);
  g_free(base_name_c);

  uint64_t access = 0;
  bool active = true;
  string content_type;

  Entry dir_entry{VERSION,     base_name, *hash,  EntryType::DIRECTORY,
                  total_size,  timestamp, access, active,
                  content_type};
  return dir_entry;
}

PBytes get_root_hash(DB& db) {
  string root_str("ROOT");
  auto root_hash = db.get((uint8_t*)&root_str[0], root_str.size());
  return move(root_hash);
}

void save_root_hash(DB& db, Bytes hash) {
  string root_str("ROOT");
  db.put((uint8_t*)&root_str[0], hash.data(), root_str.size(), hash.size(),
         OVERWRITE);
}

void join(string join_path) {
  ofstream err_file("log.err", std::ofstream::app);
  std::unique_ptr<DB> other_db = load_db(join_path, ReadOnly::Yes);

  // getting root struct
  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);

  // getting source root struct
  auto other_root_hash = get_root_hash(*other_db);
  auto other_root = other_db->load<Root>(*other_root_hash);

  for (auto other_backup_hash : other_root->backups) {
    bool add(true);
    for (auto backup_hash : root->backups)
      if (other_backup_hash == backup_hash)
        add = false;
    if (add) {  // source backup is not present, so add it
      root->backups.push_back(other_backup_hash);  // add it to root

      // now add all files
      auto src_backup = other_db->load<Backup>(other_backup_hash);
      db->store(*src_backup);

      stack<unique_ptr<Dir>> entry_hashes;
      entry_hashes.push(other_db->load<Dir>(src_backup->entry.hash));

      // run through stack, every item needs to be stored
      while (!entry_hashes.empty()) {
        auto cur_dir = move(entry_hashes.top());
        entry_hashes.pop();

        // store the dir
        db->store(*cur_dir);

        for (auto& entry : cur_dir->entries) {
          print("entry: ", entry.name);
          if (entry.hash.size() == 0) {
            print("Hash screwed up for entry: ", entry.name);
            err_file << "Hash screwed up for entry: " << entry.name << endl;
            continue;
          }
          if (entry.type == EntryType::SINGLEFILE) {
            auto data = other_db->get(entry.hash);
            db->put(*data);
          }
          if (entry.type == EntryType::MULTIFILE) {
            auto multipart = other_db->load<MultiPart>(entry.hash);
            db->store(*multipart);  // store the multipart

            for (auto part_hash : multipart->hashes) {
              auto data = other_db->get(part_hash);
              db->put(*data);  // store the data blobs
            }
          }
          if (entry.type == EntryType::DIRECTORY) {
            entry_hashes.push(other_db->load<Dir>(entry.hash));
          }
        }
      }
    }
  }

  auto new_root_hash = db->store(*root);

  save_root_hash(*db, *new_root_hash);
}

void output_file(string path, string target_path) {
  // extract the backup part
  auto backup_sep = path.find(":");
  if (backup_sep == string::npos) {
    print("need a backup seperator [backup:path]");
    return;
  }
  auto backup_name = path.substr(0, backup_sep);
  path = path.substr(backup_sep + 1);

  // remove initial slash
  auto first_slash = path.find("/");
  if (first_slash == string::npos || first_slash != 0) {
    print("path after backup should start with / (slash)");
    return;
  }
  path = path.substr(first_slash + 1);

  // loop over backups

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
            print("found file, writing to ", target_path);
            ofstream outfile(target_path);

            if (entry.type == EntryType::SINGLEFILE) {
              auto data = db->get(entry.hash);
              print("found file: ", entry.name, data->size());
              outfile.write((char*)data->data(), data->size());
              outfile.flush();
            } else if (entry.type == EntryType::MULTIFILE) {
              print("found multi file: ", entry.name);
              auto multi = db->load<MultiPart>(entry.hash);
              print("multi hash: ", multi->hashes.size());
              for (auto h : multi->hashes) {
                auto data = db->get(h);
                outfile.write((char*)data->data(), data->size());
              }
              outfile.flush();
            }
            throw StringException("Found File");
          } else {
            if (entry.name >= search_path)
              throw StringException("Problem with path");
            go = true;
            search_path = search_path.substr(current_search.size() + 1);
            dir = db->load<Dir>(entry.hash);
          }
        }
      }
    }
  }
}

void backup(GFile* path,
            string backup_name,
            string backup_description,
            bool ignore_hidden) {
  Backup backup{VERSION, backup_name, backup_description};
  {
    auto entry = enumerate(path, path, ignore_hidden);
    // auto entry_hash = db->store(entry);
    // backup.entry_hash = *entry_hash;
    backup.entry = entry;
    backup.size = entry.size;
    backup.timestamp = std::time(0);
  }

  auto backup_hash = db->store(backup);

  Root new_root;

  // See if there is already a backup
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
    print(backup->name, " ", backup->entry.hash, " ",
          user_readable_size(backup->size));
  }
}

void fix() {
  throw StringException("Dangerous!");
  auto root_hash = get_root_hash(*db);
  print("root hash ", *root_hash);
  auto root = db->load<Root>(*root_hash);

  vector<Bytes> new_backups;
  for (int b(0); b < root->backups.size(); ++b) {
    auto backup_hash = root->backups[b];
    auto backup = db->load<Backup>(backup_hash);
    print(backup->name, " ", backup->entry_hash, " ", backup->entry.hash);

    if (backup->entry.hash.empty())
      continue;
    new_backups.push_back(backup_hash);
    // if (backup->entry_hash.size()) {
    //   print("fixing ", backup->name);
    //   auto entry = db->load<Entry>(backup->entry_hash);
    //   backup->entry_hash.clear();
    //   backup->entry = *entry;
    //   auto new_bhash = db->store(*backup);
    //   root->backups[b] = *new_bhash;
    // }
  }
  root->backups = new_backups;

  auto new_root_hash = db->store(*root);
  save_root_hash(*db, *new_root_hash);
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
      /// Old loading
      auto root_entry = db->load<Entry>(backup->entry_hash);
      root_dir = db->load<Dir>(root_entry->hash);
    } else {
      // New loading
      auto root_entry = backup->entry;
      print(root_entry.hash);
      print(backup->entry_hash);
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
          println(user_readable_size(entry.size), " ",
                  cur_name + "/" + entry.name);
        else {
          q.push(move(db->load<Dir>(entry.hash)));
          name_q.push(cur_name + "/" + entry.name);
        }
      }
    }
    print(backup->name);
  }
}

unique_ptr<Entry> convert_entry(DB& target_db, Entry& entry) {
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
  if (!old_load)
    throw StringException("moveto is meant for old load");
  auto target_db = make_unique<DB>(target_db_path);

  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);

  Root new_root;
  new_root.version = 1;
  new_root.timestamp = root->timestamp;
  new_root.last_root = *root_hash;

  for (auto bhash : root->backups) {
    auto backup = db->load<Backup>(bhash);

    // conversion of old setup
    auto backup_entry = db->load<Entry>(backup->entry_hash);

    backup_entry = convert_entry(*target_db, *backup_entry);
    backup->entry = *backup_entry;
    auto backup_hash = target_db->store(*backup);
    new_root.backups.push_back(*backup_hash);
  }

  auto new_root_hash = target_db->store(new_root);
  save_root_hash(*target_db, *new_root_hash);
}

void serve(string port) {
  auto callback = [](const http::server::request& req,
                     http::server::reply& rep) {
    ostringstream output_buf;
    string content_type = "text/html";

    print("req uri: ", req.uri);
    auto slash_pos = req.uri.find('/');
    if (slash_pos < 0)
      return;
    string req_type;
    string req_string = req.uri.substr(1);

    // See if there is a second slash
    slash_pos = req_string.find('/');
    if (slash_pos != string::npos) {
      req_type = req_string.substr(0, slash_pos);
      req_string = req_string.substr(slash_pos + 1);
    }

    // these req types output the file
    cout << "req type: " << req_type << endl;
    if (req_type == "raw") {
      content_type = "text/plain";
      // Any slashes we find now encode the content-type, after the data hash
      slash_pos = req_string.find('/');
      if (slash_pos != string::npos) {
        content_type = req_string.substr(slash_pos + 1);
        req_string = req_string.substr(0, slash_pos);
      }
      Bytes search_hash;
      istringstream iss(req_string);
      iss >> search_hash;
      auto data = db->get(search_hash);
      print("serving n bytes: ", data->size(), " ", content_type);
      output_buf.write((char*)data->data(), data->size());
    }
    if (req_type == "rawmulti") {
      content_type = "text/plain";
      slash_pos = req_string.find('/');
      if (slash_pos != string::npos) {
        content_type = req_string.substr(slash_pos + 1);
        req_string = req_string.substr(0, slash_pos);
      }

      Bytes search_hash;
      istringstream iss(req_string);
      iss >> search_hash;
      auto multipart = db->load<MultiPart>(search_hash);
      for (auto hash : multipart->hashes) {
        auto data = db->get(hash);
        output_buf.write((char*)data->data(), data->size());
      }
    }

    // no req type means see if its a root or dir and output accordingly
    if (req_type == "") {
      Bytes search_hash;
      if (req_string.size() == 0) {
        auto proot = get_root_hash(*db);
        print(proot.get());

        search_hash = *proot;
      } else {
        istringstream iss(req_string);
        iss >> search_hash;
      }

      auto value = db->get(search_hash);
      if (!value) {
        rep.status = http::server::reply::not_found;
        output_buf << "No such hash: " << search_hash;

        rep.content = output_buf.str();
        rep.headers.resize(2);
        rep.headers[0].name = "Content-Length";
        rep.headers[0].value = std::to_string(rep.content.size());
        rep.headers[1].name = "Content-Type";
        rep.headers[1].value = "text/plain";
        return;
      }

      print("setting up buffer");

      string buf(value->begin(), value->end());
      istringstream iss(buf);

      // read type, and set read pointer back to 0
      uint64_t type(0);
      {
        cereal::PortableBinaryInputArchive ar(iss);
        ar(type);
        iss.seekg(0);
      }
      cereal::PortableBinaryInputArchive ar(iss);

      switch (type) {
        case (int64_t)BlobType::DIRECTORY:
          print("its a dir");
          {
            Dir dir;
            ar(dir);
            output_buf << "<html><head><title></title></head><body><ul>"
                       << endl;

            // sort by size
            // sort(dir.entries.begin(), dir.entries.end(), [](Entry const&l,
            // Entry const &r) {return l.size > r.size;});
            for (auto e : dir.entries) {
              string entry_content_type = e.content_type;
              if (entry_content_type.empty())
                entry_content_type =
                    http::server::mime_types::extension_to_type(e.name);
              if (e.type == EntryType::DIRECTORY)
                output_buf << "<li>D <a href=\"/" << e.hash << "\">" << e.name
                           << "</a> " << user_readable_size(e.size) << "</li>"
                           << endl;
              if (e.type == EntryType::SINGLEFILE)
                output_buf << "<li><a href=\"/raw/" << e.hash << "/"
                           << entry_content_type << "\">" << e.name << "</a> "
                           << user_readable_size(e.size) << "</li>" << endl;
              if (e.type == EntryType::MULTIFILE)
                output_buf << "<li><a href=\"/rawmulti/" << e.hash << "/"
                           << entry_content_type << "\">" << e.name << "</a> "
                           << user_readable_size(e.size) << "</li>" << endl;
            }
            output_buf << "</ul></body></html>";
          }
          break;
        case (int64_t)BlobType::ROOT:
          print("its a root");
          {
            Root root;
            ar(root);
            output_buf << "<html><head><title></title></head><body><ol>"
                       << endl;
            for (auto bhash : root.backups) {
              auto backup = db->load<Backup>(bhash);
              output_buf << "<li><a href=\"/" << backup->entry.hash << "\">"
                         << backup->name << "</a> "
                         << user_readable_size(backup->size) << "</li>" << endl;
            }
            output_buf << "</ol></body></html>";
          }
          break;
        default:
          print("Unknown Type");
      }
    }

    rep.content = output_buf.str();

    rep.headers.resize(2);
    rep.headers[0].name = "Content-Length";
    rep.headers[0].value = std::to_string(rep.content.size());
    rep.headers[1].name = "Content-Type";
    rep.headers[1].value = content_type;
  };

  http::server::server server(port, callback);
  server.run();
}

void export_images(std::string export_path, uint64_t min_size) {
  println("exporting images to ", export_path);

  std::set<Bytes> hash_map;

  auto root_hash = get_root_hash(*db);
  auto root = db->load<Root>(*root_hash);
  print(timestring(root->timestamp));

  for (auto bhash : root->backups) {
    auto backup = db->load<Backup>(bhash);
    auto backup_name = backup->name;

    unique_ptr<Dir> root_dir;

    if (old_load) {
      /// Old loading
      auto root_entry = db->load<Entry>(backup->entry_hash);
      root_dir = db->load<Dir>(root_entry->hash);
    } else {
      // New loading
      auto root_entry = backup->entry;
      print(root_entry.hash);
      print(backup->entry_hash);
      root_dir = db->load<Dir>(root_entry.hash);
    }

    cout << "backup " << backup_name << endl;
    cout << root_dir->entries.size() << endl;
    queue<unique_ptr<Dir>> q;
    queue<string> name_q;

    q.push(move(root_dir));
    name_q.push(backup_name);

    while (!q.empty()) {
      auto cur_dir = move(q.front());
      auto cur_name = name_q.front();
      q.pop();
      name_q.pop();

      for (auto entry : cur_dir->entries) {
        if (entry.type == EntryType::DIRECTORY) {
          q.push(move(db->load<Dir>(entry.hash)));
          name_q.push(cur_name + "/" + entry.name);
        }

        if (entry.type == EntryType::SINGLEFILE) {
          auto path = cur_name + "/" + entry.name;
          auto entry_content_type =
              http::server::mime_types::extension_to_type(entry.name);
          if (entry_content_type == "image/jpeg" ||
              entry_content_type == "image/png") {
            // Check if image was already exported

            if (entry.size < min_size) {
              println("Skipping small file");
              continue;              
            }
            if (hash_map.count(entry.hash)) {
              println("Skipping already encountered: ", path);
              continue;
            }
            hash_map.insert(entry.hash);

            // Create gfiles, and create directory
            auto target_path = export_path + "/" + path;
            println("exporting to ", target_path);

            auto target_gfile = g_file_new_for_path(target_path.c_str());
            if (!target_gfile)
              throw std::runtime_error("Failed to open file");

            auto dir_gfile = g_file_get_parent(target_gfile);
            if (!g_file_query_exists(dir_gfile, nullptr))
              if (!g_file_make_directory_with_parents(dir_gfile, nullptr,
                                                      nullptr))
                throw std::runtime_error("Failed to create directory");

            // Output the file
            ofstream outfile(target_path);
            if (!outfile) {
              throw std::runtime_error("Failed to open file");
            }
            auto data = db->get(entry.hash);
            if (!data) {
              throw std::runtime_error("Failed to load file data");
            }

            outfile.write((char*)data->data(), data->size());
            outfile.flush();

            g_object_unref(target_gfile);
            g_object_unref(dir_gfile);
          }
        }
      }
    }
  }
}

int main(int argc, char** argv) {
  cout << "Cereal Archiver" << endl;
  init_blakekey();

  // parse arguments
  args::ArgumentParser parser(
      "Cereal Archiver - lmdb and cereal based archiver");
  args::ValueFlag<string> db_path(parser, "db", "Path to DB", {"db"},
                                  "archive.db");
  args::ValueFlag<bool> read_only(parser, "read_only",
                                  "Create DB If not exists",
                                  {"read_only", "ro"}, true);

  args::Group commands(parser, "commands");

  args::Command archive_command(commands, "archive",
                                "archive a directory into the db");
  args::ValueFlag<string> arch_name(archive_command, "name",
                                    "Name for this directory in the archive",
                                    {"name"}, args::Options::Required);
  args::ValueFlag<string> arch_path(archive_command, "path",
                                    "Path to directory", {"path"},
                                    args::Options::Required);
  args::ValueFlag<string> arch_description(
      archive_command, "description", "archive description", {"description"});
  args::ValueFlag<bool> arch_ignore_hidden(
      archive_command, "ignore_hidden", "Ignore hidden files (starting with .)",
      {"ignore_hidden"}, false);

  args::Command stat_command(commands, "stat", "print db stats");
  args::Command list_command(commands, "list", "list backups");
  args::Command filelist_command(commands, "filelist",
                                 "list all files in all backups");
  args::Command check_command(commands, "check", "check hash integrity");
  args::Command move_to_command(commands, "moveto", "duplicate db");
  args::ValueFlag<string> target_db(move_to_command, "targetdb",
                                    "target path of db to move to",
                                    {"targetdb"}, args::Options::Required);

  args::Command join_command(
      commands, "join", "Import backups from source db into this database");
  args::ValueFlag<string> source_db(join_command, "source_db",
                                    "target path of db to move to",
                                    {"source_db"}, args::Options::Required);

  args::Command extract_command(commands, "extract",
                                "extract file to a target path");
  args::ValueFlag<string> file_name(extract_command, "file",
                                    "file to output, syntax: dbname:filepath",
                                    {"file"}, args::Options::Required);
  args::ValueFlag<string> file_target_path(extract_command, "target",
                                           "target path to store file",
                                           {"target"}, args::Options::Required);

  args::Command serve_command(commands, "serve",
                              "record changes to the repository");
  args::ValueFlag<string> port(serve_command, "port", "port of server",
                               {"port"}, "9090");

  args::Command fix_command(commands, "fix",
                            "record changes to the repository");

  args::Command export_images_command(
      commands, "export_images",
      "export all jpeg and png files to a directory");

  args::ValueFlag<string> export_images_path(
      export_images_command, "target_dir", "target path to export images to",
      {"target_dir"}, args::Options::Required);
  args::ValueFlag<uint64_t> min_size(
      export_images_command, "min_size", "minimum filesize to export an image",
      {"min_size"}, 0);

  args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
  args::CompletionFlag completion(parser, {"complete"});

  try {
    parser.ParseCLI(argc, argv);
  } catch (const args::Completion& e) {
    std::cout << e.what();
    return 0;
  } catch (const args::Help&) {
    std::cout << parser;
    return 0;
  } catch (const args::ParseError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  } catch (const args::ValidationError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }

  db = load_db(args::get(db_path),
               args::get(read_only) ? ReadOnly::Yes : ReadOnly::No);

  if (archive_command) {
    auto arch_path_str = args::get(arch_path);
    GFile* file = g_file_new_for_path(arch_path_str.c_str());
    backup(file, args::get(arch_name), args::get(arch_description),
           args::get(arch_ignore_hidden));
  } else if (stat_command) {
    db->print_stat();
  } else if (list_command) {
    list_backups();
  } else if (filelist_command) {
    list_all_files();
  } else if (check_command) {
    db->check_all();
  } else if (move_to_command) {
    move_to(args::get(target_db));
  } else if (extract_command) {
    output_file(args::get(file_name), args::get(file_target_path));
  } else if (join_command) {
    join(args::get(source_db));
  } else if (serve_command) {
    serve(args::get(port));
  } else if (fix_command) {
    fix();
  } else if (export_images_command) {
    export_images(args::get(export_images_path), args::get(min_size));
  } else {
    print("No command given");
  }
}
