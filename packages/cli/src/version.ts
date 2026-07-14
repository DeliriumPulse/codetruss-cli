import packageMetadata from '../package.json'

/** Single source of truth: the bundled binary and hosted release use package.json. */
export const CLI_VERSION = packageMetadata.version
