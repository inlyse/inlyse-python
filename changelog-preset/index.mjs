import { readFile } from 'node:fs/promises'
import createAngularPreset from 'conventional-changelog-angular'

// Subject of a dependabot commit eg.
// "fix(deps): bump click from 8.4.2 to 8.5.0 (#19)"
const BUMP_PATTERN = /^fix\(deps\): bump (\S+) from (\S+) to (\S+?)(?: \(#\d+\))?$/

async function readTemplate(name) {
  return readFile(new URL(name, import.meta.url), 'utf8')
}

function groupDependencyUpdates(group, ageByHash) {
  const remaining = []
  const bumpsByName = new Map()

  for (const commit of group.commits) {
    const match = commit.scope === 'deps' ? BUMP_PATTERN.exec(commit.header ?? '') : null
    if (!match) {
      remaining.push(commit)
      continue
    }
    const [, name, from, to] = match
    if (!bumpsByName.has(name)) bumpsByName.set(name, [])
    bumpsByName.get(name).push({ from, to, age: ageByHash.get(commit.hash) })
  }

  const dependencyUpdates = [...bumpsByName.entries()]
    .map(([name, bumps]) => {
      bumps.sort((a, b) => b.age - a.age)
      return { name, from: bumps[0].from, to: bumps[bumps.length - 1].to }
    })
    // If the chain ends with the start version, nothing has changed.
    .filter((update) => update.from !== update.to)
    .sort((a, b) => a.name.localeCompare(b.name))

  return { ...group, commits: remaining, dependencyUpdates }
}

export default async function createPreset() {
  const preset = await createAngularPreset()
  const [mainTemplate, headerPartial] = await Promise.all([
    readTemplate('./main.hbs'),
    readTemplate('./header.hbs')
  ])

  return {
    ...preset,
    writer: {
      ...preset.writer,
      mainTemplate,
      headerPartial,
      finalizeContext: (context, options, filteredCommits, keyCommit, commits) => {
        const ageByHash = new Map(commits.map((commit, index) => [commit.hash, index]))
        return {
          ...context,
          commitGroups: context.commitGroups
            .map((group) =>
              group.title === 'Bug Fixes' ? groupDependencyUpdates(group, ageByHash) : group
            )
            // A group without entries, does not get mentioned in the changelog
            .filter((group) => group.commits.length > 0 || group.dependencyUpdates?.length > 0)
        }
      }
    }
  }
}
