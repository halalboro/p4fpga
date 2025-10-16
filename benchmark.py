#!/usr/bin/env python3
# benchmark.py 

import subprocess
import time
import sys
import json
from pathlib import Path
import shutil
import os

class P4CompilerBenchmark:
    def __init__(self, compiler_path, test_cases_dir):
        self.compiler_path = compiler_path
        self.test_cases_dir = Path(test_cases_dir)
        self.results = []
        
        # Check if scc is available
        self.has_scc = shutil.which("scc") is not None
        if not self.has_scc:
            print("  Warning: 'scc' tool not found. Install with: go install github.com/boyter/scc/v3@latest")
            print("    Code metrics will be simplified.\n")
    
    def get_code_metrics_scc(self, output_dir):
        """Use scc tool to get detailed code metrics"""
        if not self.has_scc:
            return None
        
        hdl_dir = Path(output_dir) / "hdl"
        
        if not hdl_dir.exists():
            return None
        
        # Check if there are any .sv files
        sv_files = list(hdl_dir.glob("*.sv"))
        if not sv_files:
            return None
        
        result = subprocess.run(
            ["scc", "--format", "json", "--by-file", str(hdl_dir)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return None
        
        try:
            # scc outputs an array of file objects
            data = json.loads(result.stdout)
            
            if not data:
                return None
            
            # Aggregate metrics across all SystemVerilog files
            total_lines = 0
            total_code = 0
            total_comments = 0
            total_blanks = 0
            total_complexity = 0
            num_files = 0
            
            for file_data in data:
                # Check both "Language" and "language" (case sensitivity)
                lang = file_data.get("Language") or file_data.get("language", "")
                
                # Accept "SystemVerilog", "Verilog", or files ending in .sv
                if "verilog" in lang.lower() or "systemverilog" in lang.lower():
                    total_lines += file_data.get("Lines", 0)
                    total_code += file_data.get("Code", 0)
                    total_comments += file_data.get("Comment", 0)
                    total_blanks += file_data.get("Blank", 0)
                    total_complexity += file_data.get("Complexity", 0)
                    num_files += 1
            
            # Fallback: if no files matched by language, count all files
            if num_files == 0:
                for file_data in data:
                    total_lines += file_data.get("Lines", 0)
                    total_code += file_data.get("Code", 0)
                    total_comments += file_data.get("Comment", 0)
                    total_blanks += file_data.get("Blank", 0)
                    total_complexity += file_data.get("Complexity", 0)
                    num_files += 1
            
            return {
                "num_files": num_files,
                "total_lines": total_lines,
                "code_lines": total_code,
                "comment_lines": total_comments,
                "blank_lines": total_blanks,
                "complexity": total_complexity
            }
            
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Fallback to simple counting on parse error
            return None
    
    def get_code_metrics_simple(self, output_dir):
        """Simple fallback metrics if scc is not available"""
        hdl_dir = Path(output_dir) / "hdl"
        
        if not hdl_dir.exists():
            return {
                "num_files": 0,
                "total_lines": 0,
                "total_size_kb": 0
            }
        
        hdl_files = list(hdl_dir.glob("*.sv"))
        num_files = len(hdl_files)
        total_lines = 0
        
        for f in hdl_files:
            try:
                total_lines += len(open(f, encoding='utf-8', errors='ignore').readlines())
            except:
                pass
        
        total_size_kb = sum(f.stat().st_size for f in hdl_files) / 1024
        
        return {
            "num_files": num_files,
            "total_lines": total_lines,
            "total_size_kb": round(total_size_kb, 2)
        }
    
    def benchmark_compilation(self, p4_file):
        """Measure compilation time, memory usage, and output size"""
        # FIXED: Use proper path - create benchmarks/ in current directory
        output_dir = Path("./benchmarks") / p4_file.stem
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Convert to absolute path for compiler
        output_dir_abs = output_dir.absolute()
        
        # Measure time and memory using /usr/bin/time
        time_cmd = ["/usr/bin/time", "-v", 
                    self.compiler_path, str(p4_file), 
                    "--output-dir", str(output_dir_abs)]
        
        start = time.time()
        result = subprocess.run(
            time_cmd,
            capture_output=True,
            text=True
        )
        end = time.time()
        
        compilation_time = end - start
        success = result.returncode == 0
        
        # DEBUG: Print on failure
        if not success:
            print(f"\n    Compiler error for {p4_file.name}:")
            if result.stdout:
                print(f"    stdout: {result.stdout[:300]}")
            if result.stderr:
                # Filter out /usr/bin/time output
                error_lines = [line for line in result.stderr.split('\n') 
                              if not line.strip().startswith(('Command being timed:', 'User time', 'System time', 'Percent', 'Elapsed', 'Maximum'))]
                if error_lines:
                    print(f"    stderr: {chr(10).join(error_lines[:10])}")
        
        # Parse memory usage from /usr/bin/time output
        memory_kb = 0
        for line in result.stderr.split('\n'):
            if "Maximum resident set size" in line:
                memory_kb = int(line.split(':')[1].strip())
                break
        
        # Get code metrics using scc or fallback
        if success:
            code_metrics = None
            
            if self.has_scc:
                code_metrics = self.get_code_metrics_scc(output_dir_abs)
            
            # Fallback to simple counting if scc failed or not available
            if code_metrics is None:
                code_metrics = self.get_code_metrics_simple(output_dir_abs)
        else:
            code_metrics = {
                "num_files": 0,
                "total_lines": 0
            }
        
        return {
            "test_case": p4_file.name,
            "success": success,
            "compilation_time_sec": round(compilation_time, 3),
            "memory_usage_mb": round(memory_kb / 1024, 2),
            **code_metrics
        }
    
    def run_full_benchmark(self):
        """Run complete benchmark suite"""
        print("=" * 80)
        print("POS Compiler Benchmark")
        print("=" * 80)
        
        # Find all P4 test cases
        test_cases = list(self.test_cases_dir.glob("*.p4"))
        if not test_cases:
            print(f"\n No .p4 files found in {self.test_cases_dir}")
            return
        
        print(f"\nFound {len(test_cases)} test cases")
        print(f"Code metrics: {'scc (detailed)' if self.has_scc else 'simple counting'}")
        print(f"Output directory: ./benchmarks/\n")
        
        for p4_file in test_cases:
            print(f" Benchmarking: {p4_file.name}...", end=" ", flush=True)
            
            comp_result = self.benchmark_compilation(p4_file)
            
            if comp_result["success"]:
                print(f" {comp_result['compilation_time_sec']}s")
            else:
                print(" Failed")
            
            self.results.append(comp_result)
        
        # Generate report
        self._generate_report()
    
    def _generate_report(self):
        """Generate final benchmark report"""
        print("\n" + "=" * 80)
        print("BENCHMARK SUMMARY")
        print("=" * 80)
        
        # Save to JSON
        with open("benchmark_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        print("\n Detailed results saved to: benchmark_results.json\n")
        
        # Check if we have scc metrics
        has_scc_metrics = any(r.get('code_lines', 0) > 0 for r in self.results if r["success"])
        
        # Print summary table based on available metrics
        if has_scc_metrics:
            self._print_detailed_report()
        else:
            self._print_simple_report()
        
        # Calculate statistics
        self._print_statistics()
    
    def _print_detailed_report(self):
        """Print detailed report with scc metrics"""
        print("=" * 120)
        print(f"{'Test Case':<20} | {'Time (s)':<10} | {'Memory (MB)':<12} | "
              f"{'Files':<6} | {'Code':<7} | {'Comments':<9} | {'Blanks':<7} | "
              f"{'Complexity':<11} | {'Status':<6}")
        print("=" * 120)
        
        for result in self.results:
            status = " OK" if result["success"] else " FAIL"
            print(f"{result['test_case']:<20} | "
                  f"{result['compilation_time_sec']:>10.3f} | "
                  f"{result['memory_usage_mb']:>12.2f} | "
                  f"{result.get('num_files', 0):>6} | "
                  f"{result.get('code_lines', 0):>7} | "
                  f"{result.get('comment_lines', 0):>9} | "
                  f"{result.get('blank_lines', 0):>7} | "
                  f"{result.get('complexity', 0):>11} | "
                  f"{status:<6}")
        
        print("=" * 120)
    
    def _print_simple_report(self):
        """Print simple report without scc metrics"""
        print("=" * 100)
        print(f"{'Test Case':<20} | {'Time (s)':<10} | {'Memory (MB)':<12} | "
              f"{'Files':<6} | {'Lines':<7} | {'Size (KB)':<10} | {'Status':<6}")
        print("=" * 100)
        
        for result in self.results:
            status = " OK" if result["success"] else " FAIL"
            print(f"{result['test_case']:<20} | "
                  f"{result['compilation_time_sec']:>10.3f} | "
                  f"{result['memory_usage_mb']:>12.2f} | "
                  f"{result.get('num_files', 0):>6} | "
                  f"{result.get('total_lines', 0):>7} | "
                  f"{result.get('total_size_kb', 0):>10.2f} | "
                  f"{status:<6}")
        
        print("=" * 100)
    
    def _print_statistics(self):
        """Print overall statistics"""
        successful = [r for r in self.results if r["success"]]
        total = len(self.results)
        
        if successful:
            avg_time = sum(r["compilation_time_sec"] for r in successful) / len(successful)
            avg_memory = sum(r["memory_usage_mb"] for r in successful) / len(successful)
            
            print(f"\n STATISTICS:")
            print(f"   Success rate:         {len(successful)}/{total} ({100*len(successful)/total:.1f}%)")
            print(f"   Avg compilation time: {avg_time:.3f}s")
            print(f"   Avg memory usage:     {avg_memory:.2f} MB")
            
            # Check if we have detailed metrics
            if successful[0].get('code_lines', 0) > 0:
                avg_code = sum(r.get('code_lines', 0) for r in successful) / len(successful)
                avg_complexity = sum(r.get('complexity', 0) for r in successful) / len(successful)
                total_code = sum(r.get('code_lines', 0) for r in successful)
                total_comments = sum(r.get('comment_lines', 0) for r in successful)
                
                comment_ratio = (total_comments / total_code * 100) if total_code > 0 else 0
                
                print(f"   Avg code lines:       {int(avg_code)} lines")
                print(f"   Avg complexity:       {int(avg_complexity)}")
                print(f"   Comment ratio:        {comment_ratio:.1f}%")
            else:
                avg_lines = sum(r.get('total_lines', 0) for r in successful) / len(successful)
                print(f"   Avg output size:      {int(avg_lines)} lines")
        else:
            print(f"\n All {total} test case(s) failed")
        
        print()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 benchmark.py <compiler_path> <test_cases_dir>")
        print("Example: python3 benchmark.py ./p4c-sv ./test_cases/")
        print("\nCompiler path should be the p4c-sv executable")
        print("Test cases dir should contain .p4 files to benchmark")
        print("\nOptional: Install 'scc' for detailed code metrics:")
        print("  go install github.com/boyter/scc/v3@latest")
        sys.exit(1)
    
    compiler = sys.argv[1]
    test_dir = sys.argv[2]
    
    # Validate inputs
    if not Path(compiler).exists():
        print(f" Error: Compiler not found at {compiler}")
        sys.exit(1)
    
    if not Path(test_dir).is_dir():
        print(f" Error: Test cases directory not found: {test_dir}")
        sys.exit(1)
    
    bench = P4CompilerBenchmark(compiler, test_dir)
    bench.run_full_benchmark()