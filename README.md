Archiver : Author(Marijn Stollenga) : License(MPL V2 / see LICENSE)
===================
Backup utility to backup many filesystems into one database, stores files by hashes and stores everyfile only once. 
Especially useful if you have many duplicates because of many years of copying files everywhere (like I have).

Dependencies
==================
- Lightning Memory-Mapped Database (liblmdb) for the Database
- Cereal library for cerealisation
- Gnome Lib (glib) and (gio) for file handling / recursing
- Blake2 hash for hashing (libb2)

Usage
=================
The database is created under the name archive.db in the directory the program is called (make better).

./archiver dryrun [collection] [path]



License:
MPLv2, See LICENSE file.