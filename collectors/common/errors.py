class ParseError(Exception):
    pass


class SourceError(Exception):
    pass


class SourceGap(SourceError):
    """The saved native position is no longer available or refers to another event."""
