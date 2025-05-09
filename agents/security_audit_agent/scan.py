import os
import sys
from pathlib import Path

# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import run

def scan_directory(directory_path, model_name=None, use_ollama="false"):
    """
    Scan a directory for security vulnerabilities and generate reports.
    
    Args:
        directory_path: Path to the directory to scan
        model_name: Name of the model to use (defaults to system default)
        use_ollama: Whether to use Ollama ("true" or "false")
    """
    # If no model specified, default to deepseek-coder
    if not model_name:
        # model_name = "deepseek-r1:1.5b"
        # model_name = "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8"
        model_name = "google/gemini-1.5-flash"
        # model_name = "gemini/gemini-1.5-pro"
    
    tasks = {}
    
    # Find all Python, JavaScript, and PHP files to scan
    extensions = ['.py', '.js', '.php', '.ts', '.jsx', '.tsx', '.html', '.rb']
    for i, file_path in enumerate(Path(directory_path).glob('**/*')):
        if file_path.suffix.lower() in extensions:
            try:
                with open(file_path, 'r') as f:
                    code = f.read()
                    tasks[f"file_{i}"] = {
                        "code": code,
                        "file_path": str(file_path)
                    }
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
    
    if not tasks:
        print(f"No supported code files found in {directory_path}")
        return
    
    print(f"Found {len(tasks)} files to scan...")
    
    # Run security audit
    results = run(tasks, model_name=model_name, use_ollama=use_ollama)
    
    # Save results
    output_dir = "security_reports"
    os.makedirs(output_dir, exist_ok=True)
    
    for task_id, report in results.items():
        file_path = tasks[task_id].get("file_path", "unknown_file")
        safe_name = os.path.basename(file_path).replace(".", "_")
        output_path = f"{output_dir}/security_report_{safe_name}.md"
        
        with open(output_path, 'w') as f:
            f.write(report)
        print(f"Report saved to {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <directory_path> [model_name] [use_ollama]")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    model_name = sys.argv[2] if len(sys.argv) > 2 else None
    use_ollama = sys.argv[3] if len(sys.argv) > 3 else "false"
    
    scan_directory(directory_path, model_name, use_ollama)