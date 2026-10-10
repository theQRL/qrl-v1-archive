"""CLI failure classes specified by the archive format."""


class ArchiveError(Exception):
    exit_code = 4


class UsageError(ArchiveError):
    exit_code = 2


class SourceError(ArchiveError):
    exit_code = 3


class IntegrityError(ArchiveError):
    exit_code = 4


class DisagreementError(ArchiveError):
    exit_code = 5


class PublicationError(ArchiveError):
    exit_code = 6
