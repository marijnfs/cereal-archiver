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

using namespace std;

typedef vector<uint8_t> Bytes;
typedef unique_ptr<Bytes> PBytes;

uint HASH_BYTES(32);
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
    Dir,
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
  vector<Bytes> hashes;
  uint64_t size;

  template <class Archive>
  void serialize( Archive & ar ) {
    ar(hashes, size);
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


PBytes get_hash(Bytes &bytes) {
  auto hash = make_unique<Bytes>(HASH_BYTES);
  if (blake2b(hash->data(), bytes.data(), blakekey, HASH_BYTES, bytes.size(), BLAKE2B_KEYBYTES) < 0)
    throw StringException("hash problem");
  return hash;
}


int main() {
  init_blakekey();

  
}
