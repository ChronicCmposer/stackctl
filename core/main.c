/*
 * main.c — thin entry point for the `stackctl` binary.
 *
 * All CLI behaviour (global-flag parsing, verb resolution, help/version
 * rendering, exit-code mapping, signal policy) lives in the dispatch library;
 * `main` only hands the process command line over and returns the frozen exit
 * code. No business logic belongs here.
 */

#include "dispatch.h"

int main(int argc, char **argv) { return cli_dispatch_run(argc, argv); }
