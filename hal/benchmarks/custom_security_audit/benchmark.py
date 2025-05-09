from inspect_ai import Task, task, eval_set
from inspect_ai.dataset import Sample
from inspect_ai.scorer import match

from agent_bridge import security_audit_solver

# Example vulnerable code samples for testing security audit
SAMPLES = [
    Sample(
        input="""
        # SQL Injection Vulnerability
        def get_user(username):
            query = f"SELECT * FROM users WHERE username = '{username}'"
            return db.execute(query)
        """, 
        target=["SQL Injection"]
    ),
    Sample(
        input="""
        # XSS Vulnerability
        @app.route('/search')
        def search():
            query = request.args.get('q', '')
            return f"<h1>Search results for: {query}</h1>"
        """, 
        target=["Cross-Site Scripting"]
    ),
    Sample(
        input="""
        # Hardcoded credentials
        API_KEY = "sk_live_51L7SLjKmJY5TgRMWTGtGYwP7Grf8qkY5"
        SECRET = "c9a8d7b6e5f4a3b2c1d0"
        
        def authenticate():
            return requests.post(
                "https://api.service.com/auth",
                headers={"Authorization": f"Bearer {API_KEY}"}
            )
        """, 
        target=["Sensitive Data Exposure"]
    ),
]

@task
def security_audit_benchmark():
    """Benchmark for testing security audit capabilities"""
    return Task(
        dataset=SAMPLES,
        solver=security_audit_solver(),
        scorer=match()
    )

# Create a set of tasks for the benchmark
tasks = [security_audit_benchmark()]

if __name__ == "__main__":
    # This allows running this file directly
    eval_set(tasks, log_dir="results/security_audit_custom") 