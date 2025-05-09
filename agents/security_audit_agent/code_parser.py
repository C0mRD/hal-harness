import os
import re
from typing import Dict, Any, List

def extract_code_context(task: Dict[str, Any]) -> str:
    # Check if the code is directly in the task
    if 'code' in task:
        return task['code']
    
    # Check if code is in 'files' key
    if 'files' in task:
        files = task['files']
        # If files is a dict with file contents
        if isinstance(files, dict):
            # Combine all files into one code snippet with file markers
            all_code = []
            for filename, content in files.items():
                file_content = content
                if isinstance(content, dict) and 'content' in content:
                    file_content = content['content']
                
                all_code.append(f"# FILE: {filename}")
                all_code.append(file_content)
                all_code.append("\n")
            
            return "\n".join(all_code)
        
        # If files is a list of file paths
        elif isinstance(files, list):
            all_code = []
            for file_path in files:
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            all_code.append(f"# FILE: {file_path}")
                            all_code.append(content)
                            all_code.append("\n")
                    except Exception as e:
                        all_code.append(f"# ERROR reading {file_path}: {str(e)}")
            
            return "\n".join(all_code)
    
    # Check if code is in 'input' or 'description' fields
    for field in ['input', 'description', 'problem_statement']:
        if field in task and isinstance(task[field], str):
            # Try to extract code blocks from markdown or text
            code = extract_code_blocks(task[field])
            if code:
                return code
    
    # For Git-related tasks (like SWE-bench), check if there's a patch
    if 'patch' in task:
        return f"# PATCH:\n{task['patch']}"
    
    # If no code found, return a warning message
    return "# WARNING: No code could be extracted from the task."

def extract_code_blocks(text: str) -> str:
    # Look for markdown code blocks (```code```)
    code_blocks = re.findall(r'```(?:\w+)?\n([\s\S]*?)```', text)
    
    if code_blocks:
        return "\n\n".join(code_blocks)
    
    # Look for code blocks with 4-space indentation
    lines = text.split('\n')
    indented_blocks = []
    current_block = []
    in_block = False
    
    for line in lines:
        if line.startswith('    ') and not line.startswith('     '):
            # This is an indented code line
            if not in_block:
                in_block = True
            current_block.append(line[4:])  # Remove the 4 spaces
        else:
            # Not an indented code line
            if in_block:
                # End of a block
                indented_blocks.append('\n'.join(current_block))
                current_block = []
                in_block = False
    
    # Add the last block if there is one
    if current_block:
        indented_blocks.append('\n'.join(current_block))
    
    if indented_blocks:
        return "\n\n".join(indented_blocks)
    
    # If no code blocks found, return the original text
    # It might be a code file without any markdown formatting
    return text

def identify_language(code: str) -> str:
    # Simple heuristics to detect language
    indicators = {
        'python': ['.py', 'import ', 'def ', 'class ', '#!/usr/bin/env python', 'from ', '__init__'],
        'javascript': ['.js', 'function ', 'const ', 'let ', 'var ', 'export ', 'import ', 'require(', '=> {'],
        'typescript': ['.ts', '.tsx', 'interface ', 'type ', 'namespace '],
        'java': ['.java', 'public class ', 'private class ', 'protected class ', 'import java.', '@Override'],
        'php': ['.php', '<?php', '<?=', 'namespace ', 'use ', '->'],
        'ruby': ['.rb', 'require ', 'def ', 'class ', 'module ', 'attr_', '# frozen_string_literal'],
        'go': ['.go', 'package ', 'import (', 'func ', 'type ', 'struct {'],
        'c': ['.c', '#include <', 'int main(', 'void ', 'struct ', 'typedef '],
        'cpp': ['.cpp', '.hpp', '#include <', 'namespace ', 'template<', 'std::'],
        'csharp': ['.cs', 'using System', 'namespace ', 'public class ', 'private class '],
        'html': ['.html', '<!DOCTYPE', '<html', '<head', '<body', '<div'],
        'css': ['.css', '{', '}', '@media', 'margin:', 'padding:'],
        'sql': ['.sql', 'SELECT ', 'INSERT INTO ', 'UPDATE ', 'DELETE FROM ', 'CREATE TABLE ']
    }
    
    # Check file marker in the code
    file_match = re.search(r'# FILE: .*(\.\w+)', code)
    if file_match:
        extension = file_match.group(1).lower()
        for lang, indicators_list in indicators.items():
            if extension in indicators_list:
                return lang
    
    # Count indicators for each language
    scores = {lang: 0 for lang in indicators}
    
    for lang, indicators_list in indicators.items():
        for indicator in indicators_list:
            if indicator in code:
                scores[lang] += 1
    
    # Find language with highest score
    max_score = 0
    detected_lang = 'unknown'
    
    for lang, score in scores.items():
        if score > max_score:
            max_score = score
            detected_lang = lang
    
    return detected_lang

def extract_imports(code: str, language: str) -> List[str]:
    imports = []
    
    if language == 'python':
        # Match both 'import x' and 'from x import y'
        import_matches = re.findall(r'^import\s+([\w\.]+)', code, re.MULTILINE)
        from_matches = re.findall(r'^from\s+([\w\.]+)\s+import', code, re.MULTILINE)
        imports = import_matches + from_matches
        
    elif language in ['javascript', 'typescript']:
        # Match ES6 imports and require statements
        es6_matches = re.findall(r'import\s+.*\s+from\s+[\'"]([^\'"]*)[\'"]\s*;?', code)
        require_matches = re.findall(r'require\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)', code)
        imports = es6_matches + require_matches
        
    elif language == 'java':
        imports = re.findall(r'^import\s+([\w\.]+);', code, re.MULTILINE)
        
    elif language == 'php':
        imports = re.findall(r'use\s+([\w\\]+)(?:\s+as\s+\w+)?;', code, re.MULTILINE)
        requires = re.findall(r'require(?:_once)?\s*\(\s*[\'"]([^\'"]*)[\'"]', code)
        includes = re.findall(r'include(?:_once)?\s*\(\s*[\'"]([^\'"]*)[\'"]', code)
        imports.extend(requires + includes)
        
    return imports 