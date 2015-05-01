ttyrider: ttyrider.c
	gcc $< -o $@ -lpthread -Wall

clean:
	rm ttyrider
