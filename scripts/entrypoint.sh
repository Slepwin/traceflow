#!/usr/bin/env bash
# Container entrypoint: dispatch to agent, client, or the integration tests.
set -e
case "${1:-help}" in
  agent)     shift; exec /usr/local/bin/agent "$@" ;;
  client)    shift; exec /usr/local/bin/client "$@" ;;
  collector) shift; exec /usr/local/bin/collector "$@" ;;
  itest)   shift; exec bash /opt/traceflow/tests/run-integration.sh "$@" ;;
  sh|bash) exec bash ;;
  help|*)
    echo "traceflow container"
    echo "  agent  <args>   run the eBPF agent (needs BPF + net caps)"
    echo "  client <args>   send a marked probe"
    echo "  itest           run integration tests (needs --privileged)"
    echo "  bash            interactive shell"
    ;;
esac
