all: ttyrider ttyrider32 ttyrider64

ttyrider: ttyrider.c
	gcc $< -o $@ -lpthread -Wall

# make these static since they will probably be uploaded and run on another box
ttyrider32: ttyrider.c
	gcc $< -o $@ -lpthread -Wall -static -m32

ttyrider64: ttyrider.c
	gcc $< -o $@ -lpthread -Wall -static -m64

clean:
	rm ttyrider ttyrider32 ttyrider64
