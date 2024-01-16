.PHONY: all clean

Path ?= /Users/emmapatriciafarkash/Documents/zoom-analysis-2/frame/
ZPKT ?= zoommeeting.zpkt
INPUT_ZPKT_PATH = $(Path)$(ZPKT)
OUTPUT_CSV_PATH = $(Path)frames.csv

all: frame frames.html

frame:
	../build/zoom_rtp -i $(INPUT_ZPKT_PATH) --frames-out $(OUTPUT_CSV_PATH)
	Rscript -e "rmarkdown::render('frames.rmd')"

clean:
	rm -f frames.csv frames.html
