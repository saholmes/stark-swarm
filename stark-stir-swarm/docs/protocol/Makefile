# Build targets for the STIR-DNS swarm protocol documentation.
#
# `make pdf`     — build the LaTeX paper to swarm-protocol.pdf
# `make prove`   — run Tamarin in batch mode against the .spthy model
# `make tamarin` — open the Tamarin model interactively in a browser
# `make clean`   — drop build artifacts

PAPER       = swarm-protocol
TEX_MAIN    = $(PAPER).tex
TEX_FIGS    = figures/architecture.tex \
              figures/sequence-happy.tex \
              figures/sequence-byzantine.tex
SPTHY       = security/swarm.spthy

LATEXMK    ?= latexmk
TAMARIN    ?= tamarin-prover

.PHONY: all pdf prove tamarin clean

all: pdf

pdf: $(PAPER).pdf

$(PAPER).pdf: $(TEX_MAIN) $(TEX_FIGS)
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error -shell-escape $(TEX_MAIN)

prove:
	@command -v $(TAMARIN) > /dev/null 2>&1 || { \
	    echo "tamarin-prover not on PATH — see README.md for install instructions"; \
	    exit 1; }
	$(TAMARIN) --prove $(SPTHY)

tamarin:
	@command -v $(TAMARIN) > /dev/null 2>&1 || { \
	    echo "tamarin-prover not on PATH — see README.md for install instructions"; \
	    exit 1; }
	$(TAMARIN) interactive $(SPTHY)

clean:
	$(LATEXMK) -C $(TEX_MAIN) || true
	rm -f $(PAPER).pdf $(PAPER).synctex.gz
	rm -rf _minted-* *.fdb_latexmk *.fls *.aux *.log *.out *.toc *.bbl *.blg
