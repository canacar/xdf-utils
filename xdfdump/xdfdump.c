/*
 * Copyright (c) 2016 Can Acar
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef letoh64
#define letoh64(x) le64toh(x)
#define letoh32(x) le32toh(x)
#define letoh16(x) le16toh(x)
#endif

int dflag = 0;	/* dump -- all chunks */
int lflag = 0;	/* list -- stream headers, limited text */
int iflag = 0;  /* info -- stream headers, all XML */
int vflag = 0;	/* verbose flag */
int xflag = 0;	/* extract stream */
int sflag = 0;  /* stream id selected */

FILE *out_fd = NULL; /* output file */
int streamid = -1;	/* stream to extract or info */

struct xdf_chunk {
	off_t ch_offset;	/* after the length field */
	uint64_t ch_length;	/* after the length field */
	unsigned int ch_tag;	/* included in length */
};

struct xdf_file {
	FILE *xf_fd;
	off_t xf_size;
	off_t xf_pos;
};

typedef enum {
	XDF_TAG_FILEHDR = 1,
	XDF_TAG_STREAMHDR,
	XDF_TAG_SAMPLES,
	XDF_TAG_CLOCKOFF,
	XDF_TAG_BOUNDARY,
	XDF_TAG_STREAMFTR
} xdf_tag_t;

/* Callback for chunk processing */
typedef int (*chunk_cb_t)(struct xdf_file *xf, struct xdf_chunk *c);


int
xdf_write_uint8(FILE *out, int val)
{
	unsigned char c;
	if (val < 0 || val > 255)
		return 1;
	c = val;
	if (fwrite(&c, 1, 1, out) != 1)
		return 1;
	return 0;
}

int
xdf_write_uint16(FILE *out, int val)
{
	uint16_t v;
	if (val < 0 || val > 65535)
		return 1;
	v = htole16(val);
	if (fwrite(&v, sizeof(v), 1, out) != 1)
		return 1;
	return 0;
}

int
xdf_write_uint32(FILE *out, uint32_t val)
{
	val = htole32(val);
	if (fwrite(&val, sizeof(val), 1, out) != 1)
		return 1;
	return 0;
}

int
xdf_write_uint64(FILE *out, uint64_t val)
{
	val = htole64(val);
	if (fwrite(&val, sizeof(val), 1, out) != 1)
		return 1;
	return 0;
}

int
xdf_write_length(FILE *out, uint64_t len)
{
	int nb = 0;
	int ret = 0;
	
	if (len < 256) {
		nb = 1;
		ret = xdf_write_uint8(out, nb);
		ret |= xdf_write_uint8(out, len);
	} else if (len <= 0xffffffffULL) {
		nb = 4;
		ret = xdf_write_uint8(out, nb);
		ret |= xdf_write_uint32(out, len);
	} else {
		nb = 8;
		ret = xdf_write_uint8(out, nb);
		ret |= xdf_write_uint64(out, len);
	}

	return ret;
}

int
xdf_write_magic(FILE *out)
{
	char magic[] = {'X', 'D', 'F', ':'};

	if (fwrite(magic, sizeof(magic), 1, out) != 1)
		return 1;

	return 0;
}

uint64_t
xdf_read_uint8(struct xdf_file *xf, int *err)
{
	int v = 0;
	
	v = fgetc(xf->xf_fd);

	if (v != -1) {
		*err = 0;
		xf->xf_pos++;
	} else {
		*err = 1;
	}

	return v;
}

uint64_t
xdf_read_uint16(struct xdf_file *xf, int *err)
{
	uint16_t v = 0;

	if (fread(&v, sizeof(v), 1, xf->xf_fd) != 1) {
		*err = 1;
	} else {
		*err = 0;
		v = letoh16(v);
		xf->xf_pos += 2;
	}

	return v;
}

uint64_t
xdf_read_uint32(struct xdf_file *xf, int *err)
{
	uint32_t v = 0;

	if (fread(&v, sizeof(v), 1, xf->xf_fd) != 1) {
		*err = 1;
	} else {
		*err = 0;
		v = letoh32(v);
		xf->xf_pos += 4;
	}

	return v;
}

uint64_t
xdf_read_uint64(struct xdf_file *xf, int *err)
{
	uint64_t v = 0;

	if (fread(&v, sizeof(v), 1, xf->xf_fd) != 1) {
		*err = 1;
	} else {
		*err = 0;
		v = letoh64(v);
		xf->xf_pos += 8;
	}

	return v;
}

int
xdf_read_length(struct xdf_file *xf, uint64_t *len)
{
	int nl, ret = 1;

	nl = fgetc(xf->xf_fd);
	if (nl == -1)
		return -1;

	xf->xf_pos++;

	switch(nl) {
	case 1:
		*len = xdf_read_uint8(xf, &ret);
		break;
	case 4:
		*len = xdf_read_uint32(xf, &ret);
		break;
	case 8:
		*len = xdf_read_uint64(xf, &ret);
		break;
	}

	return ret;
}

int
xdf_get_file(FILE *fd, struct xdf_file *xf)
{
	char buf[4];
#if 0
	off_t size;

	if (fseeko(fd, 0L, SEEK_END)) {
		perror("xdf_get_file:fseek");
		return 1;
	}

	size = ftello(fd);
	rewind(fd);
#endif
	if (fread(buf, sizeof(buf), 1, fd) != 1) {
		perror ("xdf_get_file:read");
		return 1;
	}

	if (memcmp(buf, "XDF:", sizeof(buf))) {
		fprintf(stderr, "invalid magic code\n");
		return 1;
	}

	memset(xf, 0, sizeof(*xf));

	xf->xf_fd = fd;
#if 0
	xf->xf_size = size;
#endif
	xf->xf_pos = sizeof(buf);

	return 0;
}

int
xdf_get_chunk(struct xdf_file *xf, struct xdf_chunk *h)
{
	uint64_t len;
	unsigned int tag;
	int ret;

	ret = xdf_read_length(xf, &len);
	if (ret) {
		if (ret > 0)
			fprintf(stderr, "failed to read length\n");
		return 1;
	}

	h->ch_offset = xf->xf_pos;

	if (len < 2 || len > (xf->xf_size - h->ch_offset)) {
		fprintf(stderr, "xdf_get_chunk:invalid chunk length!\n");
		return 1;
	}

	h->ch_length = len; /* remove the tag length */

	tag = xdf_read_uint16(xf, &ret);
	if (ret) {
		fprintf(stderr, "failed to read tag\n");
		return 1;
	}

	h->ch_tag = tag;

	return 0;
}

int
xdf_next_chunk(struct xdf_file *xf, struct xdf_chunk *c)
{
	off_t off;
#if 0
	if (c->ch_offset > xf->xf_size ||
	    c->ch_length > (xf->xf_size - c->ch_offset)) {
		fprintf(stderr, "ch_offset:%llu, ch_length:%llu, xf_size:%llu\n",
			c->ch_offset, c->ch_length, xf->xf_size);
		return 1;
	}

	if (fseeko(xf->xf_fd, c->ch_offset + c->ch_length, SEEK_SET)) {
		perror("xdf_next_chunk:fseek:");
		return 1;
	}

	/* end of file */
	if (c->ch_offset + c->ch_length == xf->xf_size)
		return -1;
#endif
	if (c->ch_offset > xf->xf_pos)
		return 1;
	if (c->ch_length < (xf->xf_pos - c->ch_offset))
		return 1;

	off = c->ch_length - (xf->xf_pos - c->ch_offset);

	if (fseeko(xf->xf_fd, off, SEEK_CUR)) {
		while (off--) fgetc(xf->xf_fd);	/* XXX */
	}

	return 0;
}

const char *
xdf_chunk_tag(struct xdf_chunk *c)
{
	static char typestr[20];

	switch(c->ch_tag) {
	case 1:
		return "FileHeader";
	case 2:
		return "StreamHeader";
	case 3:
		return "Samples";
	case 4:
		return "ClockOffset";
	case 5:
		return "Boundary";
	case 6:
		return "StreamFooter";
	default:
		snprintf(typestr, sizeof(typestr), "Unknown (%d)", c->ch_tag);
		return typestr;
	}

	return NULL;
}

char *
xdf_read_chunk_data(struct xdf_file *xf, uint64_t size)
{
	static char *buf = NULL;
	static int buf_size = 0;

	if (size == 0)
		return 0;

	if (size >= buf_size) {
		char *tmp;
		tmp = realloc(buf, size + 1);
		if (tmp == NULL) {
			fprintf(stderr, "dump_text:error allocating %llu bytes\n",
				(unsigned long long)size);
			return NULL;
		}
		buf = tmp;
		buf_size = size + 1;
	}

	if (fread(buf, 1, size, xf->xf_fd) != size) {
		perror("read_chunk_data:fread()");
		return NULL;
	}

	xf->xf_pos += size;
	buf[size] = '\0';

	return buf;
}

int
dump_text(struct xdf_file *xf, uint64_t size)
{
	char *buf;

	buf = xdf_read_chunk_data(xf, size);

	if (buf == NULL)
		return 1;

	/* TODO: pretty print */
	printf("%s\n", buf);

	return 0;
}

int
dump_chunk(struct xdf_file *xf, struct xdf_chunk *c)
{
	int ret;
	uint32_t sid;
	uint64_t size;

	if (vflag == 0) {
		switch (c->ch_tag) {
		case XDF_TAG_SAMPLES:
		case XDF_TAG_CLOCKOFF:
		case XDF_TAG_BOUNDARY:
			return 0;
		}
	}

	printf("Chunk %s, %llu bytes\n",
	       xdf_chunk_tag(c),
	       (unsigned long long)c->ch_length);

	size = c->ch_length - 2; /* minus tag size */

	switch (c->ch_tag) {
	case XDF_TAG_STREAMHDR:
	case XDF_TAG_STREAMFTR:
	case XDF_TAG_SAMPLES:
	case XDF_TAG_CLOCKOFF:
		if (size < 4)
			return 1;
		sid = xdf_read_uint32(xf, &ret);
		if (ret)
			return 1;
		size -= 4;
		printf("  StreamID: %u\n", sid);
	}

	switch (c->ch_tag) {
	case XDF_TAG_STREAMHDR:
	case XDF_TAG_STREAMFTR:
	case XDF_TAG_FILEHDR:
		if (vflag > 1)
			dump_text(xf, size);
		break;
	}

	return 0;
}

/* XXX This handles a specific XML formatting only. Need real XML parsing */
int
stream_summary(struct xdf_file *xf, uint64_t size)
{
	char *buf, *p, *n;

	buf = xdf_read_chunk_data(xf, size);

	if (buf == NULL)
		return 1;

	for (p = buf; *p != '\0'; p = n + 1) {
		n = strchr(p, '\n');
		if (n == NULL) {
			printf(">>> %s\n", p);
			return 0;
		}
		*n = '\0';
		if (strstr(p, "<desc") != NULL)
			break;
		if (strstr(p, "info>") != NULL)
			continue;
		if (strstr(p, "<?xml") != NULL)
			continue;
		printf("%s\n", p);
	}

	return 0;
}

int
list_chunk(struct xdf_file *xf, struct xdf_chunk *c)
{
	int ret;
	uint32_t sid;
	uint64_t size;

	size = c->ch_length - 2; /* minus tag size */

	if (c->ch_tag == XDF_TAG_STREAMHDR) {
		if (size < 4)
			return 1;

		sid = xdf_read_uint32(xf, &ret);
		if (ret)
			return 1;
		size -= 4;

		printf("Stream, ID: %u\n", sid);
		stream_summary(xf, size);
	}

	return 0;
}

int
output_chunk(struct xdf_file *xf, struct xdf_chunk *c, uint32_t sid, uint64_t size)
{
	char *buf;

	buf = xdf_read_chunk_data(xf, size);

	if (buf == NULL)
		return 1;

	if (xdf_write_length(out_fd, c->ch_length))
		return 1;
	
	if (xdf_write_uint16(out_fd, c->ch_tag))
		return 1;

	switch (c->ch_tag) {
	case XDF_TAG_STREAMHDR:
	case XDF_TAG_STREAMFTR:
	case XDF_TAG_SAMPLES:
	case XDF_TAG_CLOCKOFF:
		if (xdf_write_uint32(out_fd, sid))
			return 1;
	}

	if (fwrite(buf, 1, size, out_fd) != size) {
		perror("fwrite");
		return 1;
	}

	return 0;
}

int
extract_chunk(struct xdf_file *xf, struct xdf_chunk *c)
{
	int ret;
	uint32_t sid = 0;
	uint64_t size;

	size = c->ch_length - 2; /* minus tag size */

	switch (c->ch_tag) {
	case XDF_TAG_STREAMHDR:
	case XDF_TAG_STREAMFTR:
	case XDF_TAG_SAMPLES:
	case XDF_TAG_CLOCKOFF:
		if (size < 4)
			return 1;
		sid = xdf_read_uint32(xf, &ret);
		if (ret)
			return 1;
		size -= 4;

		if (streamid != -1 && sid != streamid)
			return 0;
	}

	output_chunk(xf, c, sid, size);

	return 0;	
}

int
info_chunk(struct xdf_file *xf, struct xdf_chunk *c)
{
	int ret;
	uint32_t sid;
	uint64_t size;

	size = c->ch_length - 2; /* minus tag size */

	switch (c->ch_tag) {
	case XDF_TAG_STREAMHDR:
	case XDF_TAG_STREAMFTR:
		if (size < 4)
			return 1;
		sid = xdf_read_uint32(xf, &ret);
		if (ret)
			return 1;
		size -= 4;

		if (streamid != -1 && sid != streamid)
			return 0;
	}

	switch (c->ch_tag) {
	case XDF_TAG_STREAMFTR:
	case XDF_TAG_FILEHDR:
		if (vflag == 0)
			break;
	case XDF_TAG_STREAMHDR:
		if (streamid == -1)
			printf("Stream, ID: %u\n", sid);
		dump_text(xf, size);
		break;
	}

	return 0;	
}

int
process_xdf(FILE *f, chunk_cb_t process_chunk)
{
	struct xdf_chunk h;
	struct xdf_file xf;

	if (xdf_get_file(f, &xf))
		return 1;

	for (;;) {
		if (xdf_get_chunk(&xf, &h))
			break;

		process_chunk(&xf, &h);

		if (xdf_next_chunk(&xf, &h))
			break;
	}

	return 0;
}

void
usage(void)
{
	fprintf(stderr, "List streams\n");
	fprintf(stderr, "  xdfdump [-v] filename\n");
	fprintf(stderr, "Full XML stream information\n");
	fprintf(stderr, "  xdfdump -i [-v] [-s stream_id] filename\n");
	fprintf(stderr, "extract stream into new XDF file\n");
	fprintf(stderr, "  xdfdump -x -s stream_id -o out_filename filename\n");
	fprintf(stderr, "dump file structure\n");
	fprintf(stderr, "  xdfdump -d [-v] filename\n");
}

int
main(int argc, char *argv[])
{
	FILE *fd = NULL;
	int ch, ret;
	char *outfile = NULL;


	while ((ch = getopt(argc, argv, "dio:s:vx")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 's':
			sflag = 1;
			streamid = atol(optarg);
			break;
		case 'v':
			vflag++;
			break;
		case 'x':
			xflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		return 1;
	}

	
	if (strcmp(argv[0], "-") == 0)
		fd = stdin;
	else
		fd = fopen(argv[0], "r");

	if (fd == NULL) {
		perror("fopen");
		return 1;
	}

	if (xflag) {
		if (dflag || iflag || vflag || !sflag || outfile == NULL)
			usage();

		if (strcmp(outfile, "-") == 0)
			out_fd = stdout;
		else
			out_fd = fopen(outfile, "w");

		if (out_fd == NULL) {
			perror("open output file");
			return 1;
		}
		if (xdf_write_magic(out_fd)) {
			fprintf(stderr, "failed to write magic!\n");
			return 1;
		}

		ret = process_xdf(fd, extract_chunk);
	} else if (iflag) {
		if (dflag || outfile != NULL)
			usage();
		ret = process_xdf(fd, info_chunk);
	} else if (dflag) {
		if (sflag || outfile != NULL)
			usage();
		ret = process_xdf(fd, dump_chunk);
	} else {
		if (sflag || outfile != NULL)
			usage();
		ret = process_xdf(fd, list_chunk);
	}

	if (ret) {
		fprintf(stderr, "Error!\n");
	}
	return ret;
}
