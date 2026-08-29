agent = Agent(
    tools=[
        calculator,
        shell_tool,
        delete_file,
        send_email
    ]
)