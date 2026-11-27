# Prompt management writes

The live HTTP comparison against ContextForge v1.1.2 covered 19 requests on
SQLite, PostgreSQL, and SQLite initialized by the pinned release. It compared
status codes and JSON after normalizing generated IDs and timestamps.

The fixture creates a prompt with two arguments in declaration order, detects
required arguments from the template, and verifies successful execution by ID.
It checks duplicate names, a malformed template, and a byte limit with
multibyte text. It then renames the prompt, renders the new text, exercises
deactivation and reactivation, and deletes the prompt. Revision metadata changes
on edits. State changes keep the current version. Database checks confirm that
the catalog retains the submitted title and argument schema.

A second live comparison verified GET and POST through `X-Server-ID`.
Membership in the named virtual server is required, and unknown or unlinked
servers yield the pinned 404 response.
