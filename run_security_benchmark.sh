inspect eval inspect_evals/custom_security_audit/benchmark.py \
  --model google/gemini-1.5-flash \
  --temperature 0.2 \
  --log-dir logs \
  --max-connections 2

# echo "View results in results/security_audit_custom/"

# Run agentharm benchmark on custom security agent
# hal-eval --benchmark inspect_evals/agentharm_benign \
#   --agent_dir agents/security_audit_agent \
#   --agent_function main.run \
#   --agent_name "Security Audit Agent" \
#   -A model_name=google/gemini-1.5-flash \
#   -A task_name=benign

# Run agentharm benchmark on default agent proided by hal
# hal-eval --benchmark inspect_evals/agentharm_benign \
#   --agent_dir agents/inspect/agentharm \
#   --agent_function agentharm.default_agent \
#   --agent_name "Agent (gpt-4o-mini-2024-07-18)" \
#   -A model_name=openai/gpt-4o-mini-2024-07-18 \
#   -A task_name=benign