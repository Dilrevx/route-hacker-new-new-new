#!/usr/bin/env python3
"""Local, non-destructive fixtures for restore_cache; no real CAS is accessed."""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import restore_cache as rc

HERE=Path(__file__).resolve().parent
LAB=Path(tempfile.mkdtemp(prefix='restore-fixtures-',dir=str(HERE)))

class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='case-',dir=str(LAB)))
        self.store=self.root/'store';self.store.mkdir()
        self.manifest=self.store/'cache-retirement-plan.json'
        self.receipt=self.root/'historical.jsonl'
        candidates=[];receipts=[]
        for i in range(2):
            target=self.root/f'old-{i}/build-home/.m2/repository';target.mkdir(parents=True)
            seed=self.root/f'seed-{i}';seed.mkdir()
            candidates.append({'case_id':f'case-{i}','target_root':str(target),'seed_root':str(seed),'source_receipt':str(self.receipt),'source_pointer':f'jsonl:line:{i+1}#'})
            receipts.append({'case_id':f'case-{i}','status':'repair_attempt_failed','repair_attempt':{'status':'repair_attempt_failed','verified_maven_repository_source':str(seed),'applied_repair':{'verified_environment':{'MAVEN_USER_HOME':str(target.parent)}}}})
        self.receipt.write_text(''.join(json.dumps(x)+'\n' for x in receipts))
        rsha=hashlib.sha256(self.receipt.read_bytes()).hexdigest()
        for c in candidates:c['source_receipt_sha256']=rsha
        entries=[]
        for n,(i,rel,data,mode) in enumerate([(0,'org/example/a.jar',b'A'*31,0o644),(0,'org/example/b.jar',b'B'*8193,0o755),(1,'org/example/a.jar',b'A'*31,0o444)]):
            sha=hashlib.sha256(data).hexdigest();obj=self.store/'objects'/sha[:2]/sha[2:];obj.parent.mkdir(parents=True,exist_ok=True)
            if not obj.exists():obj.write_bytes(data)
            old=Path(candidates[i]['target_root'])/rel;old.parent.mkdir(parents=True,exist_ok=True);old.write_bytes(data)
            seed=Path(candidates[i]['seed_root'])/rel;seed.parent.mkdir(parents=True,exist_ok=True);seed.write_bytes(data)
            entries.append({'candidate':i,'relative_path':rel,'target':str(old),'seed':str(seed),'sha256':sha,'bytes':len(data),'mode':mode,'mtime_ns':1700000000123456789+n,'recovery_object':str(obj)})
        self.doc={'schema':'hcvr-cache-retirement-plan-v1','retained_store':str(self.store),'candidates':candidates,'entries':entries}
        self.write();self.dest=self.root/'new-restore'
    def write(self):self.manifest.write_text(json.dumps(self.doc))
    def run_restore(self,**kwargs):return rc.restore(self.manifest,self.dest,**kwargs)
    def must_reject(self,**kwargs):
        self.write()
        with self.assertRaises((ValueError,OSError)):self.run_restore(**kwargs)
        self.assertFalse(self.dest.exists())

    def test_restore_all_exact_bytes_mode_mtime_and_originals_unchanged(self):
        before={r['target']:Path(r['target']).read_bytes() for r in self.doc['entries']}
        out=self.run_restore();self.assertEqual(out['status'],'passed');self.assertEqual(out['restored_file_count'],3)
        for row in self.doc['entries']:
            p=self.dest/str(row['candidate'])/row['relative_path'];s=p.stat()
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),row['sha256']);self.assertEqual(s.st_size,row['bytes'])
            self.assertEqual(stat.S_IMODE(s.st_mode),row['mode']);self.assertEqual(s.st_mtime_ns,row['mtime_ns'])
            self.assertEqual(Path(row['target']).read_bytes(),before[row['target']])
        self.assertTrue((self.dest/'restore-receipt.json').is_file())
    def test_limit(self):
        r=self.run_restore(limit=1);self.assertEqual(r['restored_file_count'],1);self.assertEqual(r['mode'],'limited_test')
    def test_indices_select_small_and_other_candidate(self):
        r=self.run_restore(indices=[0,2]);self.assertEqual([x['manifest_entry_index'] for x in r['restored']],[0,2])
        self.assertFalse((self.dest/'0/org/example/b.jar').exists())
    def test_only_selected_CAS_is_read(self):
        Path(self.doc['entries'][1]['recovery_object']).write_bytes(b'bad')
        self.assertEqual(self.run_restore(indices=[0,2])['status'],'passed')
    def test_nonempty_destination_no_overwrite(self):
        self.dest.mkdir();p=self.dest/'keep';p.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.run_restore()
        self.assertEqual(p.read_bytes(),b'keep');self.assertEqual(list(self.dest.iterdir()),[p])
    def test_existing_owned_empty_destination(self):
        self.dest.mkdir(mode=0o700);self.assertEqual(self.run_restore()['status'],'passed')
    def test_inplace_target_rejected(self):
        self.dest=Path(self.doc['candidates'][0]['target_root'])/'new-subdir';self.must_reject()
    def test_retained_store_destination_rejected(self):
        self.dest=self.store/'new-subdir';self.must_reject()
    def test_absolute_relative_path_rejected(self):
        self.doc['entries'][0]['relative_path']='/etc/passwd';self.must_reject()
    def test_parent_relative_path_rejected(self):
        self.doc['entries'][0]['relative_path']='x/../a.jar';self.must_reject()
    def test_dot_and_backslash_paths_rejected(self):
        for value in ['./a.jar','x//a.jar','x\\a.jar']:
            self.doc['entries'][0]['relative_path']=value;self.must_reject()
    def test_target_binding_mismatch(self):
        self.doc['entries'][0]['target']=str(self.root/'unrelated');self.must_reject()
    def test_candidate_receipt_binding_mismatch(self):
        self.doc['candidates'][0]['target_root']=str(self.root/'unrelated');self.must_reject()
    def test_source_receipt_hash_mismatch(self):
        self.receipt.write_text('{}\n');self.must_reject()
    def test_cas_hash_mismatch(self):
        Path(self.doc['entries'][0]['recovery_object']).write_bytes(b'changed');self.must_reject()
    def test_cas_wrong_address(self):
        self.doc['entries'][0]['recovery_object']=str(self.root/'elsewhere');self.must_reject()
    def test_cas_file_symlink(self):
        p=Path(self.doc['entries'][0]['recovery_object']);saved=p.with_name('saved');p.rename(saved);p.symlink_to(saved)
        self.must_reject()
    def test_cas_parent_symlink(self):
        p=Path(self.doc['entries'][0]['recovery_object']).parent;saved=p.with_name(p.name+'-saved');p.rename(saved);p.symlink_to(saved,target_is_directory=True)
        self.must_reject()
    def test_open_regular_rejects_directory_symlink(self):
        actual=self.root/'actual';actual.mkdir();(actual/'data').write_bytes(b'bytes')
        link=self.root/'link';link.symlink_to(actual,target_is_directory=True)
        with self.assertRaises(OSError):rc.read_hashed(link/'data')
    @unittest.skipUnless(hasattr(os,'O_PATH') and os.geteuid()!=0,
                         'Linux O_PATH plus non-root permissions are required')
    def test_traverse_only_intermediate_and_readable_output_fd(self):
        gate=self.root/'traverse-only';gate.mkdir();inside=gate/'readable';inside.mkdir()
        data=inside/'data';data.write_bytes(b'traverse-only fixture')
        gate.chmod(0o100)
        try:
            with self.assertRaises(PermissionError):
                fd=os.open(gate,os.O_RDONLY|os.O_DIRECTORY)
                os.close(fd)
            sha,info,_=rc.read_hashed(data)
            self.assertEqual(sha,hashlib.sha256(b'traverse-only fixture').hexdigest())
            self.assertEqual(info.st_size,len(b'traverse-only fixture'))
            dest=inside/'new-restore'
            fd=rc.prepare_destination(dest)
            try:
                self.assertEqual(os.listdir(fd),[])
                # This would fail EBADF if the final output FD were O_PATH.
                os.fsync(fd)
                rc.write_receipt(fd,{'status':'fixture-passed'})
            finally:os.close(fd)
            self.assertTrue((dest/'restore-receipt.json').is_file())
        finally:gate.chmod(0o700)
    def test_destination_symlink(self):
        other=self.root/'other';other.mkdir();self.dest.symlink_to(other,target_is_directory=True)
        with self.assertRaises(ValueError):self.run_restore()
        self.assertEqual(list(other.iterdir()),[])
    def test_duplicate_entry(self):
        self.doc['entries'].append(copy.deepcopy(self.doc['entries'][0]));self.must_reject()
    def test_output_file_directory_collision(self):
        x=copy.deepcopy(self.doc['entries'][0]);x['relative_path']='org';x['target']=self.doc['candidates'][0]['target_root']+'/org';self.doc['entries'].append(x);self.must_reject()
    def test_special_mode_rejected(self):
        self.doc['entries'][0]['mode']=0o4755;self.must_reject()
    def test_boolean_candidate_rejected(self):
        self.doc['entries'][0]['candidate']=True;self.must_reject()
    def test_selector_errors(self):
        for kw in ({'limit':0},{'indices':[9]},{'indices':[0,0]},{'limit':1,'indices':[0]}):self.must_reject(**kw)
    def test_receipt_evidence_fallback_when_original_missing(self):
        sha=self.doc['candidates'][0]['source_receipt_sha256'];e=self.store/'evidence';e.mkdir();shutil.copy2(self.receipt,e/(sha+'.jsonl'))
        self.receipt.rename(self.receipt.with_suffix('.saved'))
        r=self.run_restore();self.assertTrue(all(x['receipt_source_mode']=='manifest_sibling_evidence' for x in r['receipt_bindings']))
    def test_bad_evidence_does_not_silently_fallback(self):
        sha=self.doc['candidates'][0]['source_receipt_sha256'];e=self.store/'evidence';e.mkdir();(e/(sha+'.jsonl')).write_text('{}\n')
        self.must_reject()
    def test_relocated_cas_with_original_missing(self):
        old=str(self.root/'nonexistent-original-store');self.doc['retained_store']=old
        for row in self.doc['entries']:row['recovery_object']=old+'/objects/'+row['sha256'][:2]+'/'+row['sha256'][2:]
        self.write();self.assertEqual(self.run_restore()['status'],'passed')
    def test_cli_indices_and_mutual_exclusion(self):
        cmd=[sys.executable,str(HERE/'restore_cache.py'),'--manifest',str(self.manifest),'--destination',str(self.dest),'--indices','0,2']
        p=subprocess.run(cmd,text=True,capture_output=True);self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['restored_file_count'],2)
        p=subprocess.run(cmd+['--limit','1'],text=True,capture_output=True);self.assertNotEqual(p.returncode,0)

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RestoreTests)
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    report={'schema':'restore-cache-local-fixture-tests-v1','status':'passed' if result.wasSuccessful() else 'failed','tests_run':result.testsRun,'failure_count':len(result.failures),'error_count':len(result.errors),'skip_count':len(result.skipped),'skipped_tests':[{'test':str(t),'reason':why} for t,why in result.skipped],'fixture_root':str(LAB),'fixtures_retained':True,'real_remote_CAS_accessed':False,'old_research_data_modified':False,'failed_tests':[str(t) for t,_ in result.failures+result.errors]}
    current=HERE/'restore-tests-report.json'
    if current.exists():
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        shutil.copy2(current,HERE/('restore-tests-report.previous-'+stamp+'.json'))
    (HERE/'restore-tests-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    raise SystemExit(0 if result.wasSuccessful() else 1)
