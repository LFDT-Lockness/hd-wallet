.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html" cargo +nightly doc --no-deps --all-features

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html" cargo +nightly doc --no-deps --all-features --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html" cargo +nightly doc --no-deps --all-features --document-private-items

readme:
	cargo readme -i src/lib.rs --no-indent-headings \
		| perl -ne 's/(?<!!)\[([^\[]+?)\]\((?!http)[^\(]+?\)/\1/g; print;' \
		| perl -ne 's/(?<!\])\[([^\[,]+?)\](?!\(|:|\[)/\1/g; print;' \
		> README.md
