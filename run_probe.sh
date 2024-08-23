ulimit -n 1048576
export BCC_PROBE_LIMIT=1048576
export PYTHONPATH=$(pwd)

python3 -m datacrumbs.main
