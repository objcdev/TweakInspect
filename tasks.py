from invoke import Context, task


@task
def lint_check(ctx: Context) -> None:
    try:
        ctx.run("isort --check .", pty=True)
    except Exception as e:
        print(e)

    try:
        ctx.run("flake8 --exclude .venv --max-line-length 120 .", pty=True)
    except Exception as e:
        print(e)

    try:
        ctx.run("black -l 120 --diff --check .", pty=True)
    except Exception as e:
        print(e)


@task
def lint(ctx: Context) -> None:
    ctx.run("isort .")
    ctx.run("autoflake --in-place --recursive .")
    ctx.run("black -l 120 --quiet .")
