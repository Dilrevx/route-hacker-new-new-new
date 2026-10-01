#!/usr/bin/env python3
"""Restore receipt-bound cached bytes from CAS into a NEW empty directory.

Usage: restore_cache.py --manifest PLAN.json --destination /new/empty/path
                        [--limit N | --indices 0,123,456]
Outputs /new/empty/path/<candidate-index>/<relative_path> and restore-receipt.json.
Never writes to old targets, never deletes anything, never executes recipes.
Receipts are loaded from manifest-parent/evidence/<sha256>.jsonl preferentially,
with original receipt paths as a fallback; hashes and logical bindings are mandatory.
CAS metadata is checked against retained_store, while a relocated sibling objects/
directory is used preferentially when the manifest and CAS were copied together.
Indices are zero-based positions in manifest.entries, not candidate indices.
Manifest JSON is parsed in memory; only selected entry paths/CAS are validated.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

BLOCK=1024*1024
NOFOLLOW=getattr(os,'O_NOFOLLOW',None)
DIRECTORY=getattr(os,'O_DIRECTORY',None)
# Linux O_PATH needs only search/traverse permission on intermediate directories.
# It is used solely for openat/mkdirat path walks, never listdir or fsync.
WALK_ACCESS=getattr(os,'O_PATH',os.O_RDONLY)

class RestoreError(ValueError):pass

def now():return dt.datetime.now(dt.timezone.utc).isoformat()
def integer(value,name,minimum=0):
    if isinstance(value,bool) or not isinstance(value,int) or value<minimum:
        raise RestoreError('Invalid integer: '+name)
    return value
def absolute(value,name):
    if not isinstance(value,str) or not value or '\x00' in value or '\\' in value:
        raise RestoreError('Invalid path: '+name)
    p=PurePosixPath(value)
    if not p.is_absolute() or any(x in ('.','..','') for x in value.split('/')[1:]):
        raise RestoreError('Absolute path must be canonical: '+name)
    return Path(value)
def relative(value):
    if not isinstance(value,str) or not value or '\\' in value or '\x00' in value:
        raise RestoreError('Invalid relative_path')
    if value.startswith('/') or any(p in ('','.','..') for p in value.split('/')) or re.match(r'^[A-Za-z]:',value):
        raise RestoreError('Unsafe relative_path')
    return value.split('/')
def overlap(a,b):
    return a==b or a in b.parents or b in a.parents
def reject_symlinks(path):
    current=Path('/')
    for part in path.parts[1:]:
        current=current/part
        try:st=current.lstat()
        except FileNotFoundError:break
        if stat.S_ISLNK(st.st_mode):raise RestoreError('Symlink in path: '+str(current))

def open_dir(path):
    """Walk without requiring directory listing permission (Linux O_PATH)."""
    if NOFOLLOW is None or DIRECTORY is None:raise RestoreError('O_NOFOLLOW/O_DIRECTORY required')
    fd=os.open('/',WALK_ACCESS|DIRECTORY|NOFOLLOW)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,WALK_ACCESS|DIRECTORY|NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        return fd
    except BaseException:
        os.close(fd);raise
def open_regular(path):
    fd=open_dir(path.parent)
    try:result=os.open(path.name,os.O_RDONLY|NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    finally:os.close(fd)
    if not stat.S_ISREG(os.fstat(result).st_mode):
        os.close(result);raise RestoreError('Not a regular input file')
    return result
def signature(st):
    return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_mode)
def read_hashed(path,return_bytes=False):
    fd=open_regular(path)
    try:
        before=os.fstat(fd);h=hashlib.sha256();chunks=[] if return_bytes else None
        while True:
            data=os.read(fd,BLOCK)
            if not data:break
            h.update(data)
            if chunks is not None:chunks.append(data)
        after=os.fstat(fd)
        if signature(before)!=signature(after):raise RestoreError('Input changed while reading')
        return h.hexdigest(),after,(b''.join(chunks) if chunks is not None else None)
    finally:os.close(fd)
def parse_receipt_pointer(text,pointer):
    match=re.fullmatch(r'jsonl:line:([1-9][0-9]*)#?',pointer or '')
    if not match:raise RestoreError('Unsupported source receipt pointer')
    lines=text.splitlines();n=int(match.group(1))
    if n>len(lines):raise RestoreError('Receipt line is out of range')
    obj=json.loads(lines[n-1])
    if not isinstance(obj,dict):raise RestoreError('Receipt is not an object')
    return obj

def validate(document,destination,manifest_path):
    if document.get('schema')!='hcvr-cache-retirement-plan-v1':raise RestoreError('Unsupported manifest schema')
    candidates=document.get('candidates');entries=document.get('entries')
    if not isinstance(candidates,list) or not candidates or not isinstance(entries,list):raise RestoreError('Missing candidates/entries')
    store=absolute(document.get('retained_store'),'retained_store');reject_symlinks(store)
    protected=[store,manifest_path,manifest_path.parent/'objects',manifest_path.parent/'evidence'];candidate_roots=[];receipt_cache={};bindings=[]
    for index,c in enumerate(candidates):
        if not isinstance(c,dict):raise RestoreError('Invalid candidate object')
        target=absolute(c.get('target_root'),'target_root');seed=absolute(c.get('seed_root'),'seed_root')
        original_source=absolute(c.get('source_receipt'),'source_receipt')
        expected_hash=c.get('source_receipt_sha256')
        if not isinstance(expected_hash,str) or not re.fullmatch('[0-9a-f]{64}',expected_hash):raise RestoreError('Invalid receipt SHA256')
        evidence=manifest_path.parent/'evidence'/(expected_hash+'.jsonl')
        reject_symlinks(evidence)
        source=evidence if evidence.is_file() else original_source
        for p in (target,seed,source):reject_symlinks(p)
        protected.extend((target,seed,source,original_source))
        for key in ('preserve_source_root','preserve_database_root'):
            if c.get(key):protected.append(absolute(c[key],key))
        if source not in receipt_cache:receipt_cache[source]=read_hashed(source,True)
        sha,_,raw=receipt_cache[source]
        if sha!=c.get('source_receipt_sha256'):raise RestoreError('Historical receipt SHA mismatch')
        obj=parse_receipt_pointer(raw.decode('utf-8'),c.get('source_pointer'))
        attempt=obj.get('repair_attempt',{})
        home=attempt.get('applied_repair',{}).get('verified_environment',{}).get('MAVEN_USER_HOME')
        if not isinstance(home,str) or absolute(home,'receipt MAVEN_USER_HOME')/'repository'!=target:
            raise RestoreError('Target root is not bound to historical receipt')
        if attempt.get('verified_maven_repository_source')!=str(seed):raise RestoreError('Seed root is not bound to historical receipt')
        if c.get('case_id')!=obj.get('case_id'):raise RestoreError('Receipt case_id mismatch')
        if target in candidate_roots:raise RestoreError('Duplicate candidate target')
        candidate_roots.append(target)
        bindings.append({'candidate':index,'case_id':c.get('case_id'),'receipt_sha256':sha,'source_pointer':c['source_pointer'],'target_root':str(target),'receipt_read_from':str(source),'receipt_source_mode':'manifest_sibling_evidence' if source==evidence else 'original_path'})
    reject_symlinks(destination)
    if any(overlap(destination,p) for p in protected):raise RestoreError('Destination intersects original target, seed, receipt, manifest, or retained store')
    seen=set();validated=[]
    for row in entries:
        if not isinstance(row,dict):raise RestoreError('Invalid entry')
        index=integer(row.get('candidate'),'candidate')
        if index>=len(candidates):raise RestoreError('Candidate index is out of range')
        parts=relative(row.get('relative_path'));key=(str(index),*parts)
        if key in seen:raise RestoreError('Duplicate output path')
        seen.add(key)
        target=absolute(row.get('target'),'entry target');reject_symlinks(target)
        if target!=candidate_roots[index].joinpath(*parts):raise RestoreError('Entry target differs from receipt-bound root/relative_path')
        sha=row.get('sha256')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise RestoreError('Invalid SHA256')
        size=integer(row.get('bytes'),'bytes');mode=integer(row.get('mode'),'mode');mtime=integer(row.get('mtime_ns'),'mtime_ns')
        if mode>0o777:raise RestoreError('Special mode bits are not permitted')
        if mtime>2**63-1:raise RestoreError('mtime_ns out of range')
        obj=absolute(row.get('recovery_object'),'recovery_object');reject_symlinks(obj)
        if obj!=store/'objects'/sha[:2]/sha[2:]:raise RestoreError('CAS path does not match the content-addressed store')
        relocated=manifest_path.parent/'objects'/sha[:2]/sha[2:]
        reject_symlinks(relocated)
        actual_object=relocated if relocated.is_file() else obj
        validated.append({'candidate':index,'relative_path':'/'.join(parts),'target':str(target),'sha256':sha,'bytes':size,'mode':mode,'mtime_ns':mtime,'recovery_object':str(actual_object),'original_recovery_object':str(obj)})
    for key in seen:
        if any(key[:i] in seen for i in range(1,len(key))):raise RestoreError('Output file/directory collision')
    return validated,bindings

def prepare_destination(destination):
    parent=open_dir(destination.parent)
    try:
        try:os.mkdir(destination.name,mode=0o700,dir_fd=parent)
        except FileExistsError:pass
        fd=os.open(destination.name,os.O_RDONLY|DIRECTORY|NOFOLLOW,dir_fd=parent)
    finally:os.close(parent)
    st=os.fstat(fd)
    if st.st_uid!=os.getuid() or st.st_mode&0o022 or os.listdir(fd):
        os.close(fd);raise RestoreError('Destination must be an owned, non-group/world-writable empty directory')
    return fd
def output_parent(rootfd,parts):
    fd=os.dup(rootfd)
    try:
        for part in parts:
            try:os.mkdir(part,0o700,dir_fd=fd)
            except FileExistsError:pass
            nxt=os.open(part,os.O_RDONLY|DIRECTORY|NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        return fd
    except BaseException:
        os.close(fd);raise
def write_receipt(rootfd,value):
    fd=os.open('restore-receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|NOFOLLOW,0o600,dir_fd=rootfd)
    with os.fdopen(fd,'w') as f:
        json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    os.fsync(rootfd)

def restore(manifest,destination,limit=None,indices=None):
    manifest=absolute(str(manifest),'manifest');destination=absolute(str(destination),'destination')
    if limit is not None:integer(limit,'limit',1)
    if limit is not None and indices is not None:raise RestoreError('limit and indices are mutually exclusive')
    sha,_,raw=read_hashed(manifest,True);document=json.loads(raw)
    del raw
    if not isinstance(document.get('entries'),list):raise RestoreError('Missing entries')
    total=len(document['entries'])
    if indices is not None:
        if not indices or len(set(indices))!=len(indices):raise RestoreError('Empty or duplicate indices')
        for index in indices:
            integer(index,'entry index')
            if index>=total:raise RestoreError('Entry index out of range')
        chosen=indices
    else:chosen=range(min(limit,total)) if limit is not None else range(total)
    selected_rows=[document['entries'][i] for i in chosen]
    document['entries']=selected_rows
    selected,bindings=validate(document,destination,manifest)
    for row,index in zip(selected,chosen):row['manifest_entry_index']=index
    # Verify selected CAS contents before creating any restore output.
    verified={}
    for row in selected:
        path=Path(row['recovery_object'])
        if path not in verified:verified[path]=read_hashed(path)[:2]
        actual,st=verified[path]
        if actual!=row['sha256'] or st.st_size!=row['bytes']:raise RestoreError('CAS SHA256/size mismatch')
    rootfd=prepare_destination(destination)
    receipt={'schema':'hcvr-cache-restore-receipt-v1','started_at_utc':now(),'manifest_sha256':sha,'manifest':str(manifest),'destination':str(destination),'mode':'indexed_test' if indices is not None else 'limited_test' if limit is not None else 'all_entries','requested_limit':limit,'requested_indices':indices,'manifest_entry_count':total,'selected_entry_count':len(selected),'validation_scope':'all candidate receipt bindings; only selected entry paths and CAS objects','receipt_bindings':bindings,'restored':[],'status':'in_progress','original_paths_modified':False,'files_deleted':0}
    try:
        for row in selected:
            parts=[str(row['candidate']),*relative(row['relative_path'])]
            parent=output_parent(rootfd,parts[:-1]);outfd=None;srcfd=None
            record={k:row[k] for k in ('manifest_entry_index','candidate','relative_path','sha256','bytes','mode','mtime_ns')}
            record.update({'output_relative_path':'/'.join(parts),'status':'started'})
            receipt['restored'].append(record)
            try:
                # Exclusive creation guarantees no existing file is overwritten.
                outfd=os.open(parts[-1],os.O_RDWR|os.O_CREAT|os.O_EXCL|NOFOLLOW,0o600,dir_fd=parent)
                srcfd=open_regular(Path(row['recovery_object']));before=os.fstat(srcfd);h=hashlib.sha256();size=0
                while True:
                    chunk=os.read(srcfd,BLOCK)
                    if not chunk:break
                    h.update(chunk);size+=len(chunk);remaining=memoryview(chunk)
                    while remaining:
                        n=os.write(outfd,remaining);remaining=remaining[n:]
                if signature(before)!=signature(os.fstat(srcfd)) or size!=row['bytes'] or h.hexdigest()!=row['sha256']:
                    raise RestoreError('CAS changed or copy integrity mismatch')
                os.fsync(outfd);os.lseek(outfd,0,os.SEEK_SET);readback=hashlib.sha256()
                while True:
                    chunk=os.read(outfd,BLOCK)
                    if not chunk:break
                    readback.update(chunk)
                if readback.hexdigest()!=row['sha256']:raise RestoreError('Restored-file readback SHA mismatch')
                os.fchmod(outfd,row['mode']);os.utime(outfd,ns=(row['mtime_ns'],row['mtime_ns']));os.fsync(outfd)
                final=os.fstat(outfd)
                if final.st_size!=row['bytes'] or stat.S_IMODE(final.st_mode)!=row['mode'] or final.st_mtime_ns!=row['mtime_ns']:
                    raise RestoreError('Restored metadata mismatch')
                record['status']='verified';os.fsync(parent)
            finally:
                if srcfd is not None:os.close(srcfd)
                if outfd is not None:os.close(outfd)
                os.close(parent)
        receipt['status']='passed';receipt['restored_file_count']=len(receipt['restored']);receipt['restored_bytes']=sum(x['bytes'] for x in receipt['restored'])
    except BaseException as exc:
        receipt['status']='failed';receipt['error_type']=type(exc).__name__;receipt['error']=str(exc)
        receipt['partial_output_retained_for_inspection']=True
        raise
    finally:
        receipt['finished_at_utc']=now()
        try:write_receipt(rootfd,receipt)
        finally:os.close(rootfd)
    return receipt

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--destination',required=True)
    selection=parser.add_mutually_exclusive_group()
    selection.add_argument('--limit',type=int)
    selection.add_argument('--indices',help='comma-separated zero-based manifest.entries indices')
    args=parser.parse_args()
    try:
        indices=None
        if args.indices is not None:
            if not re.fullmatch(r'[0-9]+(?:,[0-9]+)*',args.indices):raise RestoreError('Invalid --indices syntax')
            indices=[int(x) for x in args.indices.split(',')]
        report=restore(args.manifest,args.destination,args.limit,indices)
        print(json.dumps({k:report[k] for k in ('status','mode','restored_file_count','restored_bytes','manifest_entry_count')}))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'failed','error_type':type(exc).__name__,'error':str(exc),'original_paths_modified':False,'files_deleted':0}),file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
