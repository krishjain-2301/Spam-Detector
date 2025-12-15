import { runFileSandboxed } from '../src/sandbox.js';
import path from 'path';

const sample = path.join(process.cwd(), 'test_files', 'sample_suspicious.txt');

runFileSandboxed(sample, (result) => {
  console.log('Sandbox analysis result for', sample);
  console.log(JSON.stringify(result, null, 2));
});
