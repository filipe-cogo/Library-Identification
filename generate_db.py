#!/usr/bin/env python3

# Copyright (C) 2017 Thomas Rinsma / Riscure
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# System imports
import argparse
from dbm.ndbm import library
import sys
import gc
from tempfile import TemporaryDirectory
import tempfile

from ar import Archive, ArchiveError
from os.path import isfile, isdir, join, basename
from os import makedirs
from shutil import rmtree

# Packages
from pathos.multiprocessing import ProcessingPool as Pool

# Local files
from library_identification import ReferenceDB, LibraryFile
from prime_helpers import primesbelow


debug_enabled = True

def debug(s, tmp=False):
    """
    Prints s if the global debug_enabled is True.
    Set tmp=True to print a cariage return before the line.
    """
    global debug_enabled
    if debug_enabled:
        prefix = "## "
        if tmp:
            sys.stderr.write('\r' + prefix + s)
        else:
            sys.stderr.write(prefix + s + '\n')
        sys.stdout.flush()


def handle_library(rdb, filename, libraryname, show_progressbar=False):
    # Load the library
    ref = LibraryFile(filename)
    ref.libraryname = libraryname

    if not ref.libraryname == "":
        debug("Generating signature data for %s@%s version %s..." % (ref.name, ref.libraryname, ref.version))
    else:
        debug("Generating signature data for %s version %s..." % (ref.name, ref.version))

    # Generate string list
    ref.grab_signature_strings()

    ref.generate_r2_cfg()
    #ref.generate_cfg()

    # Save the pickle file and string file
    debug("Writing out pickle and strings for %s" % ref.basename)
    rdb.write_library(ref)

    # Garbage collect
    del ref
    gc.collect()


def main():
    # Parse cmdline arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("dbpath", metavar="db_path", type=str,
        help="Path to the DB folder, must exist.")
    parser.add_argument("references", metavar="reference", nargs="+", type=str,
        help="List of library files to process.")
    parser.add_argument("-d", "--show-db", action='store_true',
        help="Print the contents of the database and exit.")
    parser.add_argument("-p", type=int, metavar="num_processes", action='store',
        help="Number of libraries to handle in parallel.", default=1)
    parser.add_argument("-w", action='store_true',
        help="Overwrite existing signature data.")
    parser.add_argument("-c", action='store_true',
        help="Check: only print which of the files don't have signatures yet.")
    args = parser.parse_args()

    num_processes = args.p

    rdb = ReferenceDB(args.dbpath)
    if args.show_db:
        print("Signatures stored:")
        for lib_name in rdb.get_library_names():
            print("%s:" % lib_name)
            for lib_version in rdb.get_library_versions(lib_name):
                print("    %s" % lib_version)
        exit(0)


    to_be_processed = []
    for f in args.references:
        if not rdb.exists_in_db(f):
            if args.c:
                print("Not in DB yet: %s" % f)
                continue
            to_be_processed.append(f)
        else:
            if args.w:
                to_be_processed.append(f)
                print("Overwriting %s" % f)
            else:
                # TODO: check hash
                print("Skipping %s" % f)

    # check if it is a static library (archive file)
    archive_map = dict()
    tempdirs = list()
    to_be_indexed = list()
    library_name = list()
    try:
        for ref_file in to_be_processed:
            try:
                with open(ref_file, "rb") as f:
                    archive = Archive(f)
                    libname = basename(ref_file)
                    tempdir = ".%s" % libname
                    makedirs(tempdir, exist_ok=True)
                    tempdirs.append(tempdir)
                    for entry in archive:
                        with archive.open(entry.name, "rb") as e:
                            tempfile = join(tempdir, entry.name)
                            to_be_indexed.append(tempfile)
                            library_name.append(libname)
                            with open(tempfile, "wb") as lib:
                                lib.write(e.read())
                        try:
                            archive_map[ref_file].append(entry.name)
                        except KeyError:
                            archive_map[ref_file] = [entry.name]
            except ArchiveError as ae:  # not an archive file
                libname = ""
                to_be_indexed.append(ref_file)
                library_name.append(libname)

        # Start processing
        if num_processes > 1:
            debug("Generating %d CFGs, %d at a time..."
                % (len(to_be_indexed),num_processes))
            p = Pool(num_processes)
            p.map(handle_library, [rdb] * len(to_be_indexed), to_be_indexed, library_name)
        else:
            for i, ref_file in enumerate(to_be_indexed):
                handle_library(rdb, ref_file, library_name[i], show_progressbar=True)
    finally:
        for tempdir in tempdirs:
            rmtree(tempdir, ignore_errors=True)


if __name__ == "__main__":
    main()
