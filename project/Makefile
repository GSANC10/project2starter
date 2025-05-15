CC=gcc
CPPFLAGS=-Wall -Wextra
LDFLAGS=
LDLIBS=-lcrypto

### NOT RECOMMENDED:
### if you insist on developing on localhost, e.g., macOS, the following config
### may make sense to you after you run "brew install openssl"
# OPENSSL_PREFIX := /opt/homebrew/opt/openssl
# CPPFLAGS=-Wall -Wextra -I$(OPENSSL_PREFIX)/include
# LDFLAGS=-L$(OPENSSL_PREFIX)/lib

DEPS=io.o libsecurity.o security.o

all: server client gen_cert

server: server.o $(DEPS)
client: client.o $(DEPS)
gen_cert: gen_cert.o $(DEPS)

clean:
	@find . -type f \
		! -name "*.c" \
		! -name "*.h" \
		! -name "*.cpp" \
		! -name "*.hpp" \
		! -name "Makefile" \
		! -name "README.md" -delete
	@find . -type d \( ! -name "." \) -exec rm -rf {} +
