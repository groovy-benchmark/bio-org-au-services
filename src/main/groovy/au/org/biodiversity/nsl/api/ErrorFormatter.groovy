package au.org.biodiversity.nsl.api

/**
 * Turns an unexpected exception into the text returned to an API client.
 */
interface ErrorFormatter {
    String format(Throwable t)
}

/**
 * Full diagnostics, used while chasing down data problems.
 */
class VerboseErrorFormatter implements ErrorFormatter {
    @Override
    String format(Throwable t) {
        return "${t}"
    }
}

/**
 * Client-safe text only.
 */
class PublicErrorFormatter implements ErrorFormatter {
    @Override
    String format(Throwable t) {
        return 'Internal error'
    }
}
