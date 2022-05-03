#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/init.h"
#include "filesys/inode.h"
#include "filesys/off_t.h"

typedef int pid_t;

#define BUF_MAX 200

static void syscall_handler(struct intr_frame *);

static void check_boundaries(struct intr_frame *f, int no_of_args);
static bool put_user(uint8_t *udst, uint8_t byte);
static int get_user(const uint8_t *uaddr);
static void check_user_args(const void *);

void sys_exit(int status);
int sys_write(int fd, void *buffer, unsigned size);
void sys_halt(void);
int sys_exec(const char *cmd_line);
bool sys_create(const char *file, unsigned initial_size);
int sys_open(const char *file);
void sys_close(int fd);
int sys_filesize(int fd);
bool sys_remove(const char *file);
int sys_read(int fd, void *buffer, unsigned size);
int sys_wait(pid_t pid);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);

struct lock file_lock;

void syscall_init(void)
{
    // The function syscall_handler is registered as the ISR for interrupt x30
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

static void check_boundaries(struct intr_frame *f, int no_of_args)
{
    /* If threads args are not in user region, terminate. */
    if (!is_user_vaddr(f->esp + no_of_args * 4))
    {
        sys_exit(-1);
    }
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{

    check_user_args(f->esp);

    uint32_t *usp = f->esp;
    check_user_args(usp + 1);
    // Get call number off the stack
    int callno = *usp;

    switch (callno)
    {
    case SYS_HALT:
    {
        sys_halt();
        break;
    }

    case SYS_EXIT:
    {
        check_user_args(usp + 1);
        check_boundaries(f, 1);
        int exitStatus = (int)(*(usp + 1));
        sys_exit(exitStatus);
        break;
    }

    case SYS_WRITE:
    {
        // int fd;
        // void *buffer;
        // unsigned size;
        // // fd = *((int *)(f->esp + 4));
        // buffer = *((void **)(f->esp + 8));
        // size = *((unsigned *)(f->esp + 12));
        check_user_args(usp + 2);
        check_boundaries(f, 3);
        f->eax = sys_write((int)(*(usp + 1)), (void *)(*(usp + 2)), (int)(*(usp + 3)));
        break;
    }

    case SYS_EXEC:
    {
        // char *cmd_line;
        check_user_args(usp + 1);
        check_boundaries(f, 1);
        f->eax = sys_exec((char *)(*(usp + 1)));
        break;
    }

    case SYS_CREATE:
    {
        // char *file;
        // unsigned initial_size;
        check_user_args(usp + 1);
        check_boundaries(f, 2);
        f->eax = sys_create((char *)(*(usp + 1)), (unsigned)(*(usp + 2)));
        break;
    }

    case SYS_OPEN:
    {
        // char *file_name;
        check_user_args(usp + 1);
        check_boundaries(f, 1); // 1 arg
        f->eax = sys_open((char *)(*(usp + 1)));
        break;
    }

    case SYS_CLOSE:
    {
        // int fd;
        // check_user_args(usp + 1);
        check_boundaries(f, 1);
        sys_close((int)(*(usp + 1)));
        break;
    }

    case SYS_FILESIZE:
    {
        // int filFd;
        check_boundaries(f, 1); // 1 arg
        f->eax = sys_filesize((int)(*(usp + 1)));
        break;
    }

    case SYS_REMOVE:
    {
        // char *file_remove;
        check_user_args(usp + 1);
        check_boundaries(f, 1);
        f->eax = sys_remove((char *)(*(usp + 1)));
        break;
    }

    case SYS_READ:
    {
        // int filedis;
        // void *buffer_read;
        // unsigned size;
        check_user_args(usp + 2);
        check_boundaries(f, 3);
        f->eax = sys_read((int)(*(usp + 1)), (void *)(*(usp + 2)), (int)(*(usp + 3)));
        break;
    }
    case SYS_WAIT:
    {
        // pid_t pid;

        check_boundaries(f, 1);
        f->eax = sys_wait((int)(*(usp + 1)));
        break;
    }

    case SYS_SEEK:
    {
        // int fd_seek;
        // unsigned position;
        check_boundaries(f, 2);
        sys_seek((int)(*(usp + 1)), (unsigned)(*(usp + 2)));
        break;
    }

    case SYS_TELL:
    {
        // int fd_tell;
        check_boundaries(f, 1);
        f->eax = sys_tell((int)(*(usp + 1)));
        break;
    }

    default:
        thread_exit();
    }
}

unsigned sys_tell(int fd)
{
    int position;
    struct thread *curr = thread_current();
    lock_acquire(&file_lock);
    position = file_tell(curr->file_desc_table[fd]);
    lock_release(&file_lock);

    return position;
}

void sys_seek(int fd, unsigned position)
{
    struct thread *curr = thread_current();
    lock_acquire(&file_lock);
    file_seek(curr->file_desc_table[fd], position);
    lock_release(&file_lock);
}

int sys_wait(pid_t pid)
{
    int exit_status;
    exit_status = process_wait(pid);
    return exit_status;
}

int sys_read(int fd, void *buffer, unsigned size)
{

    unsigned read_byte = 0;
    // char *buffer_copy;
    struct thread *curr = thread_current();
    check_user_args(buffer);
    if (!(0 <= fd && fd < FD_TABLE_SIZE))
    {
        sys_exit(-1);
    }
    if (fd == 0)
    { // stdin
        // buffer_copy = buffer;
        //     while (size > 0)
        //     {
        //         *(buffer_copy) = input_getc();
        //         read_byte++;
        // 		buffer_copy++;
        //     }

        //     return read_byte;
        size = input_getc();
        return size;
    }
    else
    {
        if (curr->file_desc_table[fd] == NULL)
        {
            return -1;
        }
        lock_acquire(&file_lock);
        read_byte = file_read(curr->file_desc_table[fd], buffer, size);
        lock_release(&file_lock);
        return read_byte;
    }
}

// All sys call implementations follow here

/*    Terminates Pintos by calling shutdown_power_off() (declared in
      "devices/shutdown.h"). This should be seldom used, because you
      lose some information about possible deadlock situations, etc.
 */
void sys_halt(void)
{
    shutdown_power_off();
}

/*  Writes size bytes from buffer to the open file fd. Returns the
    number of bytes actually written, which may be less than size
    if some bytes could not be written.

    Writing past end-of-file would normally extend the file, but file
    growth is not implemented by the basic file system. The expected
    behavior is to write as many bytes as possible up to end-of-file
    and return the actual number written, or 0 if no bytes could be
    written at all.

    Fd 1 writes to the console. Your code to write to the console
    should write all of buffer in one call to putbuf(), at least as
    long as size is not bigger than a few hundred bytes. (It is
    reasonable to break up larger buffers.) Otherwise, lines of text
    output by different processes may end up interleaved on the
    console, confusing both human readers and our grading scripts.
*/

int sys_write(int fd, void *buffer, unsigned size)
{

    struct thread *curr = thread_current();
    // char *buffer_copy = buffer;
    if (!(0 < fd && fd < FD_TABLE_SIZE))
        return -1;

    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    else if (curr->file_desc_table[fd] == NULL)
    {
        return -1;
    }
    else
    {
        int ret_size = 0;
        lock_acquire(&file_lock);
        struct file *file = thread_current()->file_desc_table[fd];
        if (file->deny_write)
            file_deny_write(file);
        ret_size = file_write(file, buffer, size);
        lock_release(&file_lock);
        return ret_size;
    }
}

/*     Terminates the current user program, returning status to the
       kernel. If the process's parent waits for it (see below), this
       is the status that will be returned. Conventionally, a status
       of 0 indicates success and nonzero values indicate errors.
 */
void sys_exit(int status)
{
    struct thread *cur = thread_current(); // returns the current Running thread
    printf("%s: exit(%d)\n", cur->name, status);
    thread_current()->exitStatus = status;
    int index = 3;
    do
    {
        if (thread_current()->file_desc_table[index] != NULL)
        {
            sys_close(index);
        }
        index++;
    } while (index < FD_TABLE_SIZE);

    thread_exit();
}

/*     Runs the executable whose name is given in cmd_line, passing
 *     any given arguments, and returns the new process's program id
 *     (pid). Must return pid -1, which otherwise should not be a
 *     valid pid, if the program cannot load or run for any
 *     reason. Thus, the parent process cannot return from the exec
 *     until it knows whether the child process successfully loaded
 *     its executable. You must use appropriate synchronization to
 *     ensure this.
 */
// extern process_execute(const char *);

int sys_exec(const char *cmd_line)
{
    pid_t result_pid;
    check_user_args(cmd_line);
    result_pid = process_execute(cmd_line);
    return result_pid;
}

/* Creates a new file called file initially initial_size bytes in size.
Returns true if successful, false otherwise. Creating a new file does
not open it: opening the new file is a separate operation which would
require a open system call. */

bool sys_create(const char *file, unsigned initial_size)
{
    if (file == NULL)
    {
        sys_exit(-1);
    }
    bool success;
    lock_acquire(&file_lock);
    success = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return success;
}

/* Opens the file called file. Returns a nonnegative integer handle called a
"file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console:
fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output.
The open system call will never return either of these file descriptors,
which are valid as system call arguments only as explicitly described below.
Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.
When a single file is opened more than once, whether by a single process or different processes,
each open returns a new file descriptor. Different file descriptors for a single file are
closed independently in separate calls to close and they do not share a file position. */

int sys_open(const char *file_name)
{
    check_user_args(file_name);

    if (file_name == NULL)
    {
        sys_exit(-1);
    }
    lock_acquire(&file_lock);
    struct file *fp = filesys_open(file_name);
    lock_release(&file_lock);
    if (!fp)
        return -1;
    int fd;
    struct thread *curr = thread_current();
    for (fd = 3; fd < FD_TABLE_SIZE; fd++)
    {
        if (curr->file_desc_table[fd] == NULL)
        {
            if (strcmp(thread_current()->name, file_name) == 0)
            {
                file_deny_write(fp);
            }
            curr->file_desc_table[fd] = fp;
            return fd;
        }
    }
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
closes all its open file descriptors, as if by calling this function for each one. */
void sys_close(int fd)
{
    // lock_acquire(&file_lock);
    if (1 < fd && fd < FD_TABLE_SIZE)
    {
        struct file *file = thread_current()->file_desc_table[fd];
        if (!file)
            sys_exit(-1);
        thread_current()->file_desc_table[fd] = NULL;
        file_close(file);
    }
    // lock_release(&file_lock);
}

int sys_filesize(int fd)
{
    int size;
    struct thread *curr = thread_current();
    lock_acquire(&file_lock);
    size = file_length(curr->file_desc_table[fd]);
    lock_release(&file_lock);
    return size;
}

bool sys_remove(const char *file)
{
    bool success;
    lock_acquire(&file_lock);
    success = filesys_remove(file);
    lock_release(&file_lock);
    return success;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr)
{
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte));
    return error_code != -1;
}

/* Assures user address pointer + offset is in user space.
   Cleans up resources if not and kills process. */

static void check_user_args(const void *usp)
{

    struct thread *t = thread_current();
    if (usp == NULL)
    {
        sys_exit(-1);
    }
    if (!is_user_vaddr(usp) || get_user(usp) == -1 || is_kernel_vaddr(usp) || pagedir_get_page(t->pagedir, usp) == NULL)
    {
        sys_exit(-1);
    }
}
