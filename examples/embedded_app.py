"""Example: guard operations in an application you are developing."""

from agentfence import Engine, Guard
from agentfence.config import load_config


def main() -> None:
    engine = Engine(load_config("config.example.json"))
    guard = Guard(engine)
    try:
        guard.begin_turn("Read a project note")
        user_text = guard.ingest("Please read the local demo note", source="app.user")
        guard.model_request(user_text)
        guard.model_response("I will read the note.")
        content = guard.read_text("agentfence-demo.txt")
        print(guard.release_output(content.strip()))
        guard.end_turn()
    finally:
        guard.close()
        engine.close()


if __name__ == "__main__":
    main()
