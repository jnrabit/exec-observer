/*
 * exec-cases.c – Testcase-Generatoren für die Laufzeit-Kriterien von
 * exec-observer (tests/integration.sh). Wird NICHT vom Build abhängig
 * gemacht; die integration.sh übersetzt es auf Wunsch mit gcc.
 *
 * Aufrufe (jeweils ein Fall):
 *   exec-cases main_exec     <program> [args…]   execve im Hauptthread
 *   exec-cases thread_exec   <program> [args…]   execve in einem Sekundärthread
 *   exec-cases two_threads   [program]         zwei Threads execve zur selben Zeit
 *                                                (Standard /bin/sleep)
 *   exec-cases fail_exec     <pfad-einer-nicht-ausführbaren-Datei>
 *                                                execve schlägt fehl (EACCES)
 *   exec-cases memfd_exec    <name> <dauer>     memfd-ELF aus stdin, argv ["",dauer]
 *                                                (der Inhalt muss ausführbar sein)
 *   exec-cases trunc_exec    <pfad>              execve eines sehr tiefen Pfads (>256 B)
 *   exec-cases argc_exec     <n> <program>       execve mit GENAU n Argumenten
 *                                                (n = 0 → leeres argv)
 *   exec-cases deleted_exec  <program> [args…]   Kopie der Binärdatei öffnen,
 *                                                unlink, execveat(AT_EMPTY_PATH)
 *                                                (Zielverzeichnis via
 *                                                EXEC_CASES_TMPDIR, sonst /tmp)
 *   exec-cases linger        <sekunden>          nur schlafen (Ziel, das beim
 *                                                Verarbeiten noch leben muss)
 *   exec-cases nondumpable   <sekunden>           PR_SET_DUMPABLE=0, dann
 *                                                schlafen (der laufende Prozess
 *                                                ist danach für ptrace gesperrt)
 *
 * Reporter: Ist die Umgebungsvariable EXEC_CASES_REPORT_ARGV gesetzt, gibt der
 * Helfer (als Ziel von argc_exec) seinen eigenen argc aus und beendet sich –
 * so lässt sich der vom Programm gesehene argc mit dem geloggten vergleichen
 * (auch bei leerem argv, n = 0).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void die(const char *msg) __attribute__((noreturn));

static __attribute__((noreturn)) void die(const char *msg) {
    perror(msg);
    _exit(2);
}

struct thread_args {
    char **argv;
};

static void *thread_main(void *p) {
    struct thread_args *a = (struct thread_args *)p;
    execv(a->argv[0], a->argv);
    die("execv(thread_exec)");
}

static void *thread_sleep_exec(void *p) {
    /* two_threads [program]: jede der beiden Threads führt <program> aus
     * (Standard /bin/sleep). Das Argument kommt über thread_args. */
    struct thread_args *a = (struct thread_args *)p;
    char *argv[] = {a->argv[0], (char *)"0.05", NULL};
    execv(argv[0], argv);
    die("execv(two_threads)");
}

int main(int argc, char **argv) {
    /* Reporter-Modus: von argc_exec gesetzt. Der als Ziel ausgeführte Helfer
     * meldet seinen tatsächlichen argc und beendet sich – auch bei leerem
     * argv (argc kann 0 sein; argv[0] darf dann nicht dereferenziert werden). */
    if (getenv("EXEC_CASES_REPORT_ARGV") != NULL) {
        printf("child_argc=%d\n", argc);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: %s <main_exec|thread_exec|two_threads|"
                        "fail_exec|memfd_exec|trunc_exec|argc_exec|deleted_exec|"
                        "linger|nondumpable> …\n",
                argv[0]);
        return 2;
    }
    const char *mode = argv[1];

    if (strcmp(mode, "main_exec") == 0) {
        if (argc < 3) return 2;
        execv(argv[2], &argv[2]);
        die("execv(main_exec)");

    } else if (strcmp(mode, "thread_exec") == 0) {
        if (argc < 3) return 2;
        pthread_t th;
        struct thread_args a = {&argv[2]};
        if (pthread_create(&th, NULL, thread_main, &a) != 0) die("pthread_create");
        pthread_join(th, NULL);
        return 0; /* erreicht nur, wenn exec im Thread fehlschlug */

    } else if (strcmp(mode, "two_threads") == 0) {
        /* two_threads [program]: zwei Threads execve (nahezu) gleichzeitig.
         * Standardziel /bin/sleep; mit Argument private Kopie prüfbar. */
        char *av[] = {(char *)(argc >= 3 ? argv[2] : "/bin/sleep"), NULL};
        pthread_t t1, t2;
        struct thread_args a1 = {av}, a2 = {av};
        if (pthread_create(&t1, NULL, thread_sleep_exec, &a1) != 0) die("pthread_create");
        if (pthread_create(&t2, NULL, thread_sleep_exec, &a2) != 0) die("pthread_create");
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        return 0;

    } else if (strcmp(mode, "fail_exec") == 0) {
        /* Eine Datei ohne Ausführbit (0600): execve → EACCES.
         * Es darf KEIN sched_process_exec-Event entstehen. */
        if (argc < 3) return 2;
        char *fv[] = {argv[2], (char *)"x", NULL};
        int rc = execv(argv[2], fv);
        if (rc == -1 && errno == EACCES) {
            fprintf(stderr, "fail_exec: erwarteter EACCES, kein Event\n");
            return 0;
        }
        fprintf(stderr, "fail_exec: überraschender Ausgang rc=%d errno=%d\n", rc, errno);
        return 1;

    } else if (strcmp(mode, "memfd_exec") == 0) {
        /* memfd + execveat(fd, "", AT_EMPTY_PATH): der Kernel meldet den
         * «Pfad» als /memfd:<name> (deleted) → Kriterium «fileless». */
        if (argc < 4) {
            fprintf(stderr, "usage: %s memfd_exec <name> <dauer>\n", argv[0]);
            return 2;
        }
        int fd = syscall(SYS_memfd_create, "exec-cases", 0);
        if (fd < 0) die("memfd_create");
        /* Ausführbaren ELF-Inhalt (argv[2] ist nur eine Bezeichnung, der Inhalt
         * kommt aus stdin) in den memfd kopieren. */
        char buf[4096];
        ssize_t n;
        while ((n = read(0, buf, sizeof buf)) > 0) {
            if (write(fd, buf, (size_t)n) != n) die("write(memfd)");
        }
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) die("lseek");
        char *fv[] = {(char *)"" /* leeres argv[0], execveat erlaubt */,
                      argv[3], NULL};
        syscall(SYS_execveat, fd, "", fv, NULL, AT_EMPTY_PATH);
        /* Ein Shell-Skript ohne Shebang landet hier (EXECFORMAT); bei einem
         * echten ELF kehrt der Aufruf nie zurück. */
        fprintf(stderr, "memfd_exec: execveat lieferte errno=%d\n", errno);
        return 1;

    } else if (strcmp(mode, "trunc_exec") == 0) {
        /* Pfad tiefer als MAX_FILENAME (256): Kriterium path_trunc. */
        if (argc < 3) return 2;
        char *tv[] = {argv[2], NULL};
        execv(argv[2], tv);
        die("execv(trunc_exec)");

    } else if (strcmp(mode, "argc_exec") == 0) {
        /* argc_exec <n> <program> [filler…]
         * Ruft execve mit GENAU n Argumenten auf (argv[0] = program, die
         * übrigen belegt der Helfer mit "x"). n = 0 → leeres argv ({NULL}).
         * EXEC_CASES_REPORT_ARGV lässt das Ziel seinen argc berichten. */
        if (argc < 4) {
            fprintf(stderr, "usage: %s argc_exec <n> <program>\n", argv[0]);
            return 2;
        }
        long n = strtol(argv[2], NULL, 10);
        if (n < 0) {
            fprintf(stderr, "argc_exec: n < 0\n");
            return 2;
        }
        const char *prog = argv[3];
        char **av = calloc((size_t)n + 1, sizeof *av);
        if (av == NULL) die("calloc(argc_exec)");
        for (long i = 0; i < n; i++) {
            av[i] = (char *)(i == 0 ? prog : "x");
        }
        av[n] = NULL; /* Terminator: genau n Argumente */
        /* PID-Zuordnung ohne Raten: Der Helfer schreibt SEINE eigene PID
         * (getpid) direkt vor dem execve in die Argmap. Die Shell-Variante
         * mit $! war nicht verlässlich (Verschiebung um eine Stufe, s. Lauf). */
        const char *argmap = getenv("EXEC_CASES_ARGMAP");
        if (argmap != NULL && argmap[0] != '\0') {
            FILE *f = fopen(argmap, "a");
            if (f == NULL) die("fopen(argmap)");
            fprintf(f, "%ld %ld\n", n, (long)getpid());
            if (fclose(f) != 0) die("fclose(argmap)");
        }
        if (setenv("EXEC_CASES_REPORT_ARGV", "1", 1) != 0) die("setenv");
        syscall(SYS_execve, prog, av, environ);
        fprintf(stderr, "argc_exec: n=%ld execve errno=%d\n", n, errno);
        return 1;

    } else if (strcmp(mode, "deleted_exec") == 0) {
        /* deleted_exec <program> [args…]
         * Deterministischer deleted-Fall: Binärdatei in ein Temp-Verzeichnis
         * kopieren, die Kopie öffnen, sie löschen (unlink) und über den
         * offenen Deskriptor per execveat(AT_EMPTY_PATH) starten. Die Datei
         * ist damit zum Ausführungszeitpunkt bereits "(deleted)"; der Hash
         * kommt aus dem offenen FD und bleibt der des Originals. */
        if (argc < 3) {
            fprintf(stderr, "usage: %s deleted_exec <program> [args…]\n", argv[0]);
            return 2;
        }
        int in = open(argv[2], O_RDONLY | O_CLOEXEC);
        if (in < 0) die("open(deleted_exec source)");
        /* Zielverzeichnis für die gelöschte Kopie: EXEC_CASES_TMPDIR (private
         * Kopie je Phase, B1) oder Fallback /tmp. */
        char tmpl[4096];
        const char *tmpd = getenv("EXEC_CASES_TMPDIR");
        if (tmpd != NULL && tmpd[0] != '\0') {
            if (snprintf(tmpl, sizeof tmpl, "%s/exec-cases-del.XXXXXX", tmpd)
                >= (int)sizeof tmpl) {
                fprintf(stderr, "deleted_exec: TMPDIR zu lang\n");
                return 2;
            }
        } else {
            strcpy(tmpl, "/tmp/exec-cases-del.XXXXXX");
        }
        int tfd = mkstemp(tmpl);
        if (tfd < 0) die("mkstemp(deleted_exec)");
        char buf[65536];
        ssize_t r;
        while ((r = read(in, buf, sizeof buf)) > 0) {
            ssize_t off = 0;
            while (off < r) {
                ssize_t w = write(tfd, buf + off, (size_t)(r - off));
                if (w < 0) die("write(deleted_exec copy)");
                off += w;
            }
        }
        if (r < 0) die("read(deleted_exec source)");
        close(in);
        /* Ausführbit setzen: execveat prüft MAY_EXEC auf dem Inode. */
        if (fchmod(tfd, 0755) != 0) die("fchmod(deleted_exec copy)");
        close(tfd);
        int fd = open(tmpl, O_RDONLY | O_CLOEXEC);
        if (fd < 0) die("open(deleted_exec copy)");
        if (unlink(tmpl) != 0) die("unlink(deleted_exec copy)");
        /* argv[0] = program, danach die übergebenen Argumente (argv ist
         * NULL-terminiert ab argv[argc]). */
        char **dv = &argv[2];
        syscall(SYS_execveat, fd, "", dv, environ, AT_EMPTY_PATH);
        /* Nur bei Fehler erreicht (z. B. kein ausführbares ELF). */
        fprintf(stderr, "deleted_exec: execveat errno=%d\n", errno);
        return 1;

    } else if (strcmp(mode, "linger") == 0) {
        /* linger <sekunden>: nur schlafen, dann sauber beenden. Wird gebraucht,
         * wenn das Ziel beim Verarbeiten des Ereignisses noch leben muss
         * (setuid-Fälle, Marker). Ohne exec-Vorbedingung. */
        long s = 3;
        if (argc >= 3 && strtol(argv[2], NULL, 10) > 0) {
            s = strtol(argv[2], NULL, 10);
        }
        struct timespec ts = {s, 0};
        nanosleep(&ts, NULL);
        return 0;

    } else if (strcmp(mode, "nondumpable") == 0) {
        /* nondumpable <sekunden>: PR_SET_DUMPABLE(0) und dann schlafen. Der
         * beobachtete Prozess ist der Ausführende selbst (der exec des Helfers
         * erzeugt das Ereignis, der prctl danach sperrt ihn gegen ptrace ohne
         * CAP_SYS_PTRACE). Hinweis: zwischen exec und prctl liegt ein kurzer
         * Moment – der Daemon kann theoretisch vorher lesen; deshalb wird der
         * Fall mehrmals gefahren. */
        long s = 3;
        if (argc >= 3 && strtol(argv[2], NULL, 10) > 0) {
            s = strtol(argv[2], NULL, 10);
        }
        if (prctl(PR_SET_DUMPABLE, 0) != 0) {
            die("prctl(PR_SET_DUMPABLE,0)");
        }
        struct timespec ts = {s, 0};
        nanosleep(&ts, NULL);
        return 0;

    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }
}