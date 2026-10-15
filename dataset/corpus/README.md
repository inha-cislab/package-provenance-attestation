# Top-1,000 package lists

Frame: 2026-08-22. Ranked, highest first.

| ecosystem | source | metric | window | rank 1 |
|---|---|---|---|---|
| pypi | ecosyste.ms | downloads | preceding month | `boto3` |
| npm | ecosyste.ms | dependent packages | cumulative | `typescript` |
| rubygems | ecosyste.ms | downloads | cumulative | `bundler` |
| maven | ecosyste.ms | dependent packages | cumulative | `junit:junit` |
| nuget | ecosyste.ms | downloads | cumulative | `Microsoft.Extensions.DependencyInjection.Abstractions` |
| packagist | ecosyste.ms | downloads | cumulative | `symfony/polyfill-mbstring` |
| go | ecosyste.ms | dependent packages | cumulative | `golang.org/x/sys` |
| crates | ecosyste.ms | downloads | cumulative | `hashbrown` |

```
<ecosystem>.txt   1,000 names, one per line
corpus.csv        ecosystem, rank, package
MANIFEST.json     source, metric, SHA-256 per file
```

Names use each registry's own form: `owner/name`,
`groupId:artifactId`, full module path.

Metrics differ because the ranking service counts downloads for some
registries and dependent packages for others.

The fixed list preserves unresolved records returned by the ranking source.
In particular, `retract` appears at Go rank 951 but has no release version.
