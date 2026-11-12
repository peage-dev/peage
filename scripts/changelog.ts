import defaultChangelog from '@changesets/cli/changelog'

type ChangelogFunctions = typeof defaultChangelog

/**
 * All packages share one version, so most are bumped without a changeset of their own. The default
 * then lists their updated dependencies with no "Updated dependencies" line above them.
 */
const getDependencyReleaseLine: ChangelogFunctions['getDependencyReleaseLine'] = async (
  changesets,
  dependenciesUpdated,
  options,
) => {
  const lines = await defaultChangelog.getDependencyReleaseLine(
    changesets,
    dependenciesUpdated,
    options,
  )
  return changesets.length > 0 || lines === '' ? lines : `- Updated dependencies\n${lines}`
}

/** Changesets' default changelog, with every dependency list under its heading. */
const changelog: ChangelogFunctions = {
  getReleaseLine: defaultChangelog.getReleaseLine,
  getDependencyReleaseLine,
}

export default changelog
