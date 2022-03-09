#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh" >&3 2>&1
}

teardown_file() {
    load "../lib/teardown_file.sh" >&3 2>&1
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}

# to silence shellcheck
declare stderr

#----------

@test "$FILE cscli version" {
    run -0 cscli version
    assert_output --partial "version:"
    assert_output --partial "Codename:"
    assert_output --partial "BuildDate:"
    assert_output --partial "GoVersion:"
    assert_output --partial "Platform:"
    assert_output --partial "Constraint_parser:"
    assert_output --partial "Constraint_scenario:"
    assert_output --partial "Constraint_api:"
    assert_output --partial "Constraint_acquis:"
}

@test "$FILE cscli alerts list: at startup returns one entry: community pull" {
    loop_max=15
    for ((i=0; i<=loop_max; i++)); do
        sleep 2
        run -0 cscli alerts list -o json
        [[ "$output" != "null" ]] && break
    done
    run -0 jq -r '. | length' <(output)
    assert_output 1
}

@test "$FILE cscli capi status" {
    run -0 cscli capi status
    assert_output --partial "Loaded credentials from"
    assert_output --partial "Trying to authenticate with username"
    assert_output --partial " on https://api.crowdsec.net/"
    assert_output --partial "You can successfully interact with Central API (CAPI)"
}

@test "$FILE cscli config show -o human" {
    run -0 cscli config show -o human
    assert_output --partial "Global:"
    assert_output --partial "Crowdsec:"
    assert_output --partial "cscli:"
    assert_output --partial "Local API Server:"
}

@test "$FILE cscli config show -o json" {
    run -0 cscli config show -o json
    assert_output --partial '"API":'
    assert_output --partial '"Common":'
    assert_output --partial '"ConfigPaths":'
    assert_output --partial '"Crowdsec":'
    assert_output --partial '"Cscli":'
    assert_output --partial '"DbConfig":'
    assert_output --partial '"Hub":'
    assert_output --partial '"PluginConfig":'
    assert_output --partial '"Prometheus":'
}

@test "$FILE cscli config show -o raw" {
    run -0 cscli config show -o raw
    assert_line "api:"
    assert_line "common:"
    assert_line "config_paths:"
    assert_line "crowdsec_service:"
    assert_line "cscli:"
    assert_line "db_config:"
    assert_line "plugin_config:"
    assert_line "prometheus:"
}

@test "$FILE cscli config show --key" {
    run -0 cscli config show --key Config.API.Server.ListenURI
    assert_output "127.0.0.1:8080"
}

@test "$FILE cscli config backup" {
    tempdir=$(mktemp -u -p "${BATS_TEST_TMPDIR}")
    run -0 cscli config backup "${tempdir}"
    assert_output --partial "Starting configuration backup"
    run -1 --separate-stderr cscli config backup "${tempdir}"

    run -0 echo "$stderr"
    assert_output --partial "Failed to backup configurations"
    assert_output --partial "file exists"
    rm -rf -- "${tempdir:?}"
}

@test "$FILE cscli lapi status" {
    run -0 --separate-stderr cscli lapi status

    run -0 echo "$stderr"
    assert_output --partial "Loaded credentials from"
    assert_output --partial "Trying to authenticate with username"
    assert_output --partial " on http://127.0.0.1:8080/"
    assert_output --partial "You can successfully interact with Local API (LAPI)"
}

@test "$FILE cscli metrics" {
    run -0 cscli lapi status
    run -0 --separate-stderr cscli metrics
    assert_output --partial "ROUTE"
    assert_output --partial '/v1/watchers/login'

    run -0 echo "$stderr"
    assert_output --partial "Local Api Metrics:"
}