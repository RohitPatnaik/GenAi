#!/usr/bin/env python3
"""
OpenAI Generator Module

Generates Python exploit scripts for a given CVE using OpenAI.
Saves prompts per attempt, and returns the generated script or error.
"""

import os
import sys
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import openai
from config import OPENAI_API_KEY, MAX_OPENAI_ATTEMPTS, KNOWLEDGEBASE_DIR
from utils.file_utils import get_cve_script_path, ensure_cve_dir

# Configure OpenAI
openai.api_key = OPENAI_API_KEY

logger = logging.getLogger(__name__)

# Ensure directories exist
PROMPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'prompts')
os.makedirs(PROMPTS_DIR, exist_ok=True)
os.makedirs(KNOWLEDGEBASE_DIR, exist_ok=True)

def build_initial_prompt(cve: str, title: str, description: str) -> str:
    """Build the initial prompt for a given CVE."""
    prompt = f"""
You are an expert security researcher and Python developer. Write a Python script to exploit CVE {cve}.

Vulnerability Title: {title}
Description: {description}

The script should:
- Accept a target URL as the first command-line argument (sys.argv[1]).
- Check if the target is vulnerable (optional).
- If vulnerable, attempt to exploit it and print relevant output.
- Be safe: do not cause harm, only demonstrate the exploit conceptually.
- Include error handling and timeouts.
- Use only standard library or common requests library (if needed).
- The script should exit with code 0 if exploit succeeds, non-zero otherwise.

Write only the Python code, no explanations.
"""
    return prompt.strip()

def build_revised_prompt(previous_prompt: str, error_log: str, failure_reason: str) -> str:
    """Based on failure analysis, revise the prompt for a better script."""
    prompt = f"""
The previous attempt to generate an exploit script for this CVE failed. Here is the prompt used:

--- PROMPT START ---
{previous_prompt}
--- PROMPT END ---

The script generated from that prompt was executed and produced the following error/failure:

--- ERROR LOG START ---
{error_log}
--- ERROR LOG END ---

Analysis of failure: {failure_reason}

Please generate an improved Python script that addresses these issues. Follow the same requirements as before.
"""
    return prompt.strip()

def save_prompt(cve: str, attempt: int, prompt: str):
    """Save the prompt used for a given CVE and attempt."""
    prompt_dir = os.path.join(PROMPTS_DIR, cve)
    os.makedirs(prompt_dir, exist_ok=True)
    prompt_file = os.path.join(prompt_dir, f"attempt_{attempt}.txt")
    with open(prompt_file, 'w') as f:
        f.write(prompt)
    logger.info(f"Prompt saved: {prompt_file}")

def generate_script_with_openai(prompt: str) -> Optional[str]:
    """Call OpenAI API to generate a Python script from the prompt."""
    try:
        # Using ChatCompletion with a system message
        response = openai.ChatCompletion.create(
            model="gpt-4",  # or "gpt-3.5-turbo" if you prefer
            messages=[
                {"role": "system", "content": "You are a helpful assistant that writes Python exploit scripts."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1500
        )
        script = response.choices[0].message.content.strip()
        # Attempt to extract code block if present
        if "```python" in script:
            script = script.split("```python")[1].split("```")[0].strip()
        elif "```" in script:
            script = script.split("```")[1].split("```")[0].strip()
        return script
    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}")
        return None

def save_generated_script(cve: str, script: str) -> str:
    """Save the generated script to knowledgebase."""
    ensure_cve_dir(cve)
    script_path = get_cve_script_path(cve)
    with open(script_path, 'w') as f:
        f.write(script)
    # Make executable (optional)
    os.chmod(script_path, 0o755)
    logger.info(f"Script saved: {script_path}")
    return script_path

def generate_script(cve: str, title: str, description: str, log_analyzer_func) -> Tuple[bool, Optional[str], Dict]:
    """
    Attempt to generate a working exploit script for the CVE.
    Returns: (success, script_path_or_error_message, attempts_data)
    attempts_data contains details of each attempt (prompt, error, etc.)
    """
    attempts_data = {
        "cve": cve,
        "attempts": []
    }
    current_prompt = build_initial_prompt(cve, title, description)
    
    for attempt in range(1, MAX_OPENAI_ATTEMPTS + 1):
        logger.info(f"Attempt {attempt}/{MAX_OPENAI_ATTEMPTS} for {cve}")
        save_prompt(cve, attempt, current_prompt)
        
        script_content = generate_script_with_openai(current_prompt)
        if not script_content:
            err_msg = "OpenAI generation failed"
            attempts_data["attempts"].append({
                "attempt": attempt,
                "prompt": current_prompt,
                "error": err_msg,
                "script": None
            })
            # If generation fails, maybe break or continue? We'll continue to next attempt.
            continue
        
        # Save script temporarily (maybe to a temp location) for testing? 
        # But testing is done by executor, which will be called by orchestrator.
        # For now, we just save it and consider success if we have a script.
        # In the full flow, the orchestrator will test it. We'll return success if script generated.
        script_path = save_generated_script(cve, script_content)
        attempts_data["attempts"].append({
            "attempt": attempt,
            "prompt": current_prompt,
            "script": script_content,
            "script_path": script_path
        })
        
        # In this simplified version, we assume success if script is generated.
        # The orchestrator will later run the executor and if it fails, it will call log_analyzer to revise prompt.
        # For now, we return success=True, and let orchestrator handle testing.
        return True, script_path, attempts_data
    
    # If all attempts fail to generate a script
    return False, "Failed to generate script after max attempts", attempts_data
