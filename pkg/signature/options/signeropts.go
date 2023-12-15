//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import (
	"github.com/gobars/sigstore/pkg/signature/myhash"
)

// RequestCryptoSignerOpts implements the functional option pattern for supplying crypto.SignerOpts when signing or verifying
type RequestCryptoSignerOpts struct {
	NoOpOptionImpl
	opts myhash.SignerOpts
}

// ApplyCryptoSignerOpts sets crypto.SignerOpts as a functional option
func (r RequestCryptoSignerOpts) ApplyCryptoSignerOpts(opts *myhash.SignerOpts) {
	*opts = r.opts
}

// WithCryptoSignerOpts specifies that provided crypto.SignerOpts be used during signing and verification operations
func WithCryptoSignerOpts(opts myhash.SignerOpts) RequestCryptoSignerOpts {
	var optsToUse myhash.SignerOpts = myhash.SHA256
	if opts != nil {
		optsToUse = opts
	}
	return RequestCryptoSignerOpts{opts: optsToUse}
}
