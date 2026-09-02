"""
ai/
===
QuantumScyther AI — LLM Integration Layer

This layer handles LANGUAGE TASKS ONLY.
Security decisions are made exclusively by engine/.

Modules
-------
latex_parser  — LaTeX protocol notation → Protocol AST  (few-shot LLM)
explainer     — Engine attack trace → Plain English explanation + fix suggestion

Architectural rule
------------------
- LLMs translate input and generate explanations.
- LLMs NEVER make security decisions.
- All explanations are grounded in engine output — never independently generated.
- If no API key is available, the system falls back to YAML manual input.
"""
