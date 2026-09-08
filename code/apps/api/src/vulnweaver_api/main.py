"""API process entry point."""

import uvicorn


def main() -> None:
    uvicorn.run("vulnweaver_api.app:create_app", factory=True, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
