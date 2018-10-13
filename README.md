# omniauth-patreon

[![Gem Version](https://badge.fury.io/rb/omniauth-patreon.svg)](http://badge.fury.io/rb/omniauth-patreon)
[![Build Status](https://travis-ci.org/signalnerve/omniauth-patreon.svg?branch=master)](https://travis-ci.org/signalnerve/omniauth-patreon)

Patreon OAuth2 Strategy for OmniAuth 1.x and supports the OAuth 2.0 server-side flow.

You may view the Patreon API documentation [here](https://www.patreon.com/portal/).

This project is a fork from [omniauth/omniauth-patreon](https://github.com/omniauth/omniauth-patreon), reconfigured for the Patreon API 🙂

## Installation

Add to your `Gemfile`:

```ruby
gem 'omniauth-patreon'
```

Then `bundle install`.

## Usage

`OmniAuth::Strategies::Patreon` is simply Rack middleware. Read the OmniAuth 1.0 docs for detailed instructions: https://github.com/intridea/omniauth.

Here's a quick example, adding the middleware to a Rails app in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :patreon, ENV['PATREON_CLIENT_ID'], ENV['PATREON_CLIENT_SECRET']
end
```

## Configuration

- `scope`: A _space separated_ list of permissions you want to request from the Patreon API (e.g: `users my-campaign`). View the Patreon API docs for [Scope](https://docs.patreon.com/#scopes). Default: `users pledges-to-me my-campaign`

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :patreon, ENV['patreon_CLIENT_ID'], ENV['patreon_CLIENT_SECRET'], scope: 'campaigns pledges'
end
```

## Auth Hash

Here's an example _Auth Hash_ available in `request.env['omniauth.auth']`:

```ruby
{
  provider: 'patreon',
  access_token: 'abc123token',
  refresh_token: 'def456token',
  expires_in: '2018-10-13T19:00:51+00:00',
  scope: 'campaign pledges'
  token_type: "Bearer"
}
```

## Supported Ruby Versions

`omniauth-patreon` is tested under 2.2.6, 2.3.3, 2.4.1, and ruby-head.

## Versioning

This library aims to adhere to [Semantic Versioning 2.0.0][semver]. Violations
of this scheme should be reported as bugs. Specifically, if a minor or patch
version is released that breaks backward compatibility, that version should be
immediately yanked and/or a new version should be immediately released that
restores compatibility. Breaking changes to the public API will only be
introduced with new major versions. As a result of this policy, you can (and
should) specify a dependency on this gem using the [Pessimistic Version
Constraint][pvc] with two digits of precision. For example:

    spec.add_dependency 'omniauth-patreon', '~> 1.0'

[semver]: http://semver.org/
[pvc]: http://docs.rubygems.org/read/chapter/16#page74

## License

Copyright (c) 2014-2017 by Kristian Freeman

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
