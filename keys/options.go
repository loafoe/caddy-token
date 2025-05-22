package keys

type OptionFunc func(kr *keyRequest) error

type keyRequest struct {
	k          Key
	signingKey string
}

func WithOrganization(org string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Organization = org
		return nil
	}
}

func WithEnvironment(env string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Environment = env
		return nil
	}
}

func WithRegion(region string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Region = region
		return nil
	}
}

func WithProject(project string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Project = project
		return nil
	}
}

func WithScopes(scopes []string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Scopes = scopes
		return nil
	}
}

func WithExpires(expires int64) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Expires = expires
		return nil
	}
}

func WithToken(token string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Token = token
		return nil
	}
}

func WithVersion(version string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.k.Version = version
		return nil
	}
}

func WithSigningKey(signingKey string) OptionFunc {
	return func(kr *keyRequest) error {
		kr.signingKey = signingKey
		return nil
	}
}
