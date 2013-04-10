# OmniAuth Clever

Unofficial OmniAuth strategy for [Clever SSO OAuth2](https://getclever.com/developers/docs/oauth) integration.

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-clever', git: 'git://github.com/thinkthroughmath/omniauth-clever.git'

And then execute:

    $ bundle

## Usage

OmniAuth Clever is Rack Middleware in the OmniAuth convention. See the
[OmniAuth 1.0 docs](https://github.com/intridea/omniauth) for more information.

Follow the Clever OAuth docs to register your application, set callback URLs,
and get a client ID and client secret.

Example: In `config/initializers/omniauth.rb`, do:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :clever, ENV['CLEVER_CLIENT_ID'], ENV['CLEVER_CLIENT_SECRET']
end
```

## Configuring

TODO: Support setting the clever_landing param on a per-request basis

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

MIT. See LICENSE.txt.