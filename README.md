# secrets-searcher

Search for sensitive information stored in one or more git repositories.

This repository was inspired by [truffleHog](https://github.com/trufflesecurity/truffleHog) and [shhgit](https://github.com/eth0izzle/shhgit).

## Build

```shell script
cd ~/go/src/github.com/afbase
git clone git@github.com:afbase/secrets-searcher.git
cd secrets-searcher
make
```

## Github Organization usage

Obtain a GitHub token with `repo` access to the repositories you want to scan. To generate a new token, log into
GitHub, then go to "Settings > Developer settings > Personal access tokens > Generate new token".

Then run:

```shell script
cd example_config
export SECRETS_SOURCE_API_TOKEN="[GITHUB_TOKEN]"
../secrets-searcher --config="config.yaml,config.rules.yaml"
```

The tool will create an `./output/report` directory that includes an HTML report.

## License

secrets-searcher is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Its built-in detector patterns are derived from [trufflehog](https://github.com/trufflesecurity/trufflehog),
which is AGPL-3.0, so the project as a whole is distributed under the same terms. If you run a modified
version as a network service, the AGPL requires you to offer its source to the users of that service.

The original Pantheon Systems code was released under the MIT License, which is kept in
[LICENSE-MIT](LICENSE-MIT). Attribution for trufflehog and shhgit is in [NOTICE](NOTICE).
