ttyrider: ttyrider.c
	gcc $< -o $@ -lpthread

clean:
	rm ttyrider
