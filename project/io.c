#include <stdint.h>
#include <sys/fcntl.h>
#include <unistd.h>


/**
 * init_io:
 *   Configure standard input (stdin) to non-blocking mode.
 *   After this call, read() on STDIN_FILENO will return immediately
 *   if no data is available, rather than blocking.
 */

//How we set standard input to non-blocking mode
void init_io() {
    //Get current file status flags for stdin
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    //Add the 0_NONBLOCK flag to enable non-blocking reads
    flags |= O_NONBLOCK;
    //Set the updated flags back on stdin
    fcntl(STDIN_FILENO, F_SETFL, flags);
}


/**
 * input_io:
 *   Attempt to read up to max_length bytes from stdin into buf.
 *   Uses non-blocking read; if no data is available or on error,
 *   returns 0. Otherwise returns the number of bytes read (>0).
 *
 * @param buf         Buffer to fill with input data
 * @param max_length  Maximum number of bytes to read
 * @return Number of bytes read (>0), or 0 if none/error
 */

//How input_io() performs a non-blocking read and normalizes errors/empty reads to zero
ssize_t input_io(uint8_t* buf, size_t max_length) {
    //Perform the read from standard input
    ssize_t len = read(STDIN_FILENO, buf, max_length);
    //If read returns a positive count, return it; otherwise treat as no data
    return len > 0 ? len : 0;
}

/**
 * output_io:
 *   Write exactly 'length' bytes from buf to standard output (stdout).
 *   Blocks until data is written or error occurs.
 *
 * @param buf     Buffer containing data to write
 * @param length  Number of bytes to write
 */

//How output_io() writes raw bytes to stdout
void output_io(uint8_t* buf, size_t length) {
    //Write the buffer to standard output
    write(STDOUT_FILENO, buf, length);
}
