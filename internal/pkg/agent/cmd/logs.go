// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	// 1KB, it's a size of the file chunk we read for searching lines starting
	// from the end of the file
	logBufferSize = 1024
	// when follow logs, on each interval we check log file updates and if a new file appeared
	watchInterval = 500 * time.Millisecond
)

var (
	logFilePattern  = regexp.MustCompile(`elastic-agent(-event-log)?-(\d+)(-\d+)?\.ndjson$`)
	errLineFiltered = errors.New("this line was filtered out")
)

// filter for each log line, returns `true` if we print the line
type filterFunc func([]byte) bool

// modifier for each log line, returns a modified message.
// If a modification is anything other than replacing characters
// the new value must be allocated (byte slice).
type modifierFunc func([]byte) []byte

// logEntry represents a part of the elastic agent log entry
type logEntry struct {
	Component struct {
		ID string `json:"id"`
	} `json:"component"`
	LogLevel string `json:"log.level"`
}

// createComponentFilter creates a new log entry filter that
// lets print only the log lines that contain the given component ID.
func createComponentFilter(id string) filterFunc {
	return func(entry []byte) bool {
		var e logEntry
		err := json.Unmarshal(entry, &e)
		if err != nil {
			return false
		}
		return e.Component.ID == id
	}
}

func addColorModifier(entry []byte) []byte {
	var e logEntry
	err := json.Unmarshal(entry, &e)
	if err != nil {
		return entry
	}
	switch strings.ToLower(e.LogLevel) {

	case logp.InfoLevel.String():
		return []byte(color.CyanString(string(entry)))
	case logp.WarnLevel.String():
		return []byte(color.YellowString(string(entry)))
	case logp.ErrorLevel.String():
		return []byte(color.RedString(string(entry)))
	case logp.CriticalLevel.String():
		return []byte(color.HiRedString(string(entry)))
	default:
		return entry
	}
}

// stackWriter collects written byte slices and then pops them in
// the reversed (LIFO) order.
// Supports filtering and modification of each written byte slice.
type stackWriter struct {
	lines    [][]byte
	filter   filterFunc
	modifier modifierFunc
}

// Write implements `io.Writer`
func (s *stackWriter) Write(line []byte) (int, error) {
	if s.filter != nil && !s.filter(line) {
		return 0, errLineFiltered
	}
	// we must allocate and copy to preserve the state,
	// `line` is normally a slice on the reading buffer which
	// gets overwritten
	l := make([]byte, len(line))
	copy(l, line)

	if s.modifier != nil {
		l = s.modifier(l)
	}

	s.lines = append(s.lines, l)
	return len(l), nil
}

// PopAll pops every line from the stack and writes into `w` in LIFO order.
func (s stackWriter) PopAll(w io.Writer) error {
	for i := len(s.lines) - 1; i >= 0; i-- {
		_, err := w.Write(s.lines[i])
		if err != nil {
			return fmt.Errorf("failed to print the log line to the writer: %w", err)
		}
		_, err = w.Write([]byte{'\n'})
		if err != nil {
			return fmt.Errorf("failed to print the log line to the writer: %w", err)
		}
	}

	return nil
}

// newWrappedWriter create a writer proxy that filters out log lines according to the given `filter`
func newWrappedWriter(ctx context.Context, w io.Writer, filter filterFunc, modifier modifierFunc) io.Writer {
	pr, pw := io.Pipe()
	scanner := bufio.NewScanner(pr)
	go func() {
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				line := scanner.Bytes()
				if filter != nil && !filter(line) {
					continue
				}
				if modifier != nil {
					line = modifier(line)
				}
				_, _ = w.Write(line)
				_, _ = w.Write([]byte{'\n'})
			}
		}
	}()

	return pw
}

func newLogsCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	logsDir := filepath.Join(paths.Home(), logger.DefaultLogDirectory)
	eventLogsDir := filepath.Join(logsDir, "events")

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Output Elastic Agent logs",
		Long:  "This command allows to output, watch and filter Elastic Agent logs.",
		Run: func(c *cobra.Command, _ []string) {
			if err := logsCmd(streams, c, logsDir, eventLogsDir); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolP("follow", "f", false, "Do not stop when end of file is reached, but rather to wait for additional data to be appended to the log file.")
	cmd.Flags().BoolP("no-color", "", false, "Do not apply colors to different log levels.")
	cmd.Flags().IntP("number", "n", 10, "Maximum number of lines at the end of logs to output.")
	cmd.Flags().Bool("exclude-events", false, "Excludes events log files")

	cmd.Flags().StringP("component", "C", "", "Filter logs and output only logs for the given component ID.")

	return cmd
}

func logsCmd(streams *cli.IOStreams, cmd *cobra.Command, logsDir, eventLogsDir string) error {
	component, _ := cmd.Flags().GetString("component")
	lines, _ := cmd.Flags().GetInt("number")
	follow, _ := cmd.Flags().GetBool("follow")
	noColor, _ := cmd.Flags().GetBool("no-color")
	excludeEvents, _ := cmd.Flags().GetBool("exclude-events")

	var (
		filter   filterFunc
		modifier modifierFunc
	)

	if component != "" {
		filter = createComponentFilter(component)
	}

	if !noColor {
		modifier = addColorModifier
	}

	// uncomment for debugging
	// fmt.Fprintf(streams.Err, "logs dir: %q", logsDir)

	errChan := make(chan error)

	go func() {
		err := printLogs(cmd.Context(), streams.Out, logsDir, lines, follow, filter, modifier)
		if err != nil {
			errChan <- fmt.Errorf("failed to get logs: %w", err)
			return
		}
		errChan <- nil
	}()

	if !excludeEvents {
		go func() {
			done := false
			// The event log folder might not exist, so we keep trying every five seconds
			for !done {
				err := printLogs(cmd.Context(), streams.Out, eventLogsDir, lines, follow, filter, modifier)
				if err != nil {
					if !strings.Contains(err.Error(), "logs/events: no such file or directory") {
						errChan <- fmt.Errorf("failed to get event logs: %w", err)
						return
					}
					time.Sleep(5 * time.Second)
				}

				done = true
			}
		}()
	}

	if err := <-errChan; err != nil {
		return err
	}

	return nil
}

// printLogs prints the last `lines` number of log lines from the log files in `dir`
// applying the `filter` and printing all the log lines to `w`.
// if `follow` is true it will keep printing all the log updates afterwards.
func printLogs(ctx context.Context, w io.Writer, dir string, lines int, follow bool, filter filterFunc, modifier modifierFunc) error {
	files, err := getLogFilenames(dir)
	if err != nil {
		return fmt.Errorf("failed to fetch log filenames: %w", err)
	}
	if len(files) == 0 {
		return nil
	}

	stackWriter := &stackWriter{
		filter:   filter,
		modifier: modifier,
	}

	var (
		fileIndex = len(files) - 1
		printed   = 0
	)

	buf := make([]byte, logBufferSize)

	// we need to store the file size ASAP before it changes by new lines
	// but right before we start looking for the last N lines in this file
	// to minimize likelihood of corrupted output
	fileToFollow := files[fileIndex]
	followOffset, err := getFileSize(fileToFollow)
	if err != nil {
		return fmt.Errorf("failed to prepare for watching file %q: %w", fileToFollow, err)
	}

	// start looking for the N lines among all log files started with the most recent one
	for {
		filename := files[fileIndex]
		// try to read the requested amount of lines from the end of the file
		justPrinted, err := printLogFile(filename, lines-printed, stackWriter, buf)
		if err != nil {
			return fmt.Errorf("failed to print log file %q: %w", filename, err)
		}
		// account for what we've read in total, to stop once we reached the given number
		printed += justPrinted
		if printed >= lines {
			break
		}
		// if we have not read/printed enough lines, we switch to the previous file and repeat
		fileIndex--
		if fileIndex < 0 {
			break
		}
	}

	// all log lines written above were written in LIFO order, we need to invert that
	// while writing to the destination writer
	err = stackWriter.PopAll(w)
	if err != nil {
		return fmt.Errorf("failed to write the requested number of lines: %w", err)
	}

	if follow {
		output := w

		if filter != nil || modifier != nil {
			output = newWrappedWriter(ctx, w, filter, modifier)
		}
		err = watchLogsDir(ctx, dir, fileToFollow, followOffset, output)
		if err != nil {
			return fmt.Errorf("failed to follow the logs: %w", err)
		}
	}

	return nil
}

// printLogFile reads the target file defined by the absolute path `filename` backwards in chunks
// defined by the size of the given `buf`  until it finds enough lines defined by `maxLines`
// or the whole file is read. Prints all found lines to `w` in LIFO order.
func printLogFile(filename string, maxLines int, w *stackWriter, buf []byte) (linesWritten int, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("failed to open log file %q for reading: %w", filename, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to stat log file %q: %w", filename, err)
	}
	offset := info.Size()
	bufferSize := int64(len(buf))

	var leftOverBuf []byte

	// reading chunks in reverse starting with the end of the file and try to find
	// lines up to the requested amount, once found - stop
	for {
		offset -= bufferSize
		if offset < 0 {
			// shorten the buffer so we don't read anything extra during the
			// last iteration of `ReadAt`
			buf = buf[0 : bufferSize+offset]
			// this chunk is smaller than the buffer
			offset = 0
		}

		bytesRead, err := file.ReadAt(buf, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return linesWritten, fmt.Errorf("failed to read from log file %q: %w", filename, err)
		}

		chunk := buf[:bytesRead]

		// the current chunk must contain leftovers (incomplete entry) from the previous chunk
		if len(leftOverBuf) != 0 {
			newChunk := make([]byte, len(chunk)+len(leftOverBuf))
			copy(newChunk[:len(chunk)], chunk)
			copy(newChunk[len(chunk):], leftOverBuf)
			chunk = newChunk
			leftOverBuf = nil
		}

		// the first entry ends at the end for the current chunk
		entryEnd := len(chunk)
		for i := len(chunk) - 1; i >= 0; i-- {
			if chunk[i] != '\n' {
				continue
			}

			// the log entry excluding the new line character
			entry := chunk[i+1 : entryEnd]
			// the next entry will end where this entry starts
			entryEnd = i

			// if it's a trailing new line, the entry is empty
			if len(entry) == 0 {
				continue
			}

			_, err := w.Write(entry)
			if errors.Is(err, errLineFiltered) {
				continue
			}
			if err != nil {
				return linesWritten, fmt.Errorf("failed to print log line: %w", err)
			}
			linesWritten++
			if linesWritten == maxLines {
				return linesWritten, nil
			}
		}

		// if the last new line character was found somewhere in the middle of the chunk
		// we keep the rest which will join the next chunk
		if entryEnd != 0 {
			leftOverBuf = make([]byte, entryEnd)
			copy(leftOverBuf, chunk[:entryEnd])
		}

		// if there is nothing left to read from the file
		if offset == 0 {
			break
		}
	}

	// the very last part of the chunk without a new line character becomes
	// the final line
	if len(leftOverBuf) > 0 {
		_, err := w.Write(leftOverBuf)
		if errors.Is(err, errLineFiltered) {
			return linesWritten, nil
		}
		if err != nil {
			err = fmt.Errorf("failed to print log line: %w", err)
			return linesWritten, err
		}
		linesWritten++
	}
	return linesWritten, nil
}

// getLogFilenames returns absolute paths to all log files in `dir` sorted in the log rotation order.
func getLogFilenames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to list logs directory: %w", err)
	}

	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !logFilePattern.MatchString(e.Name()) {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}

	sortLogFilenames(paths)

	return paths, nil
}

// sortLogFilenames sorts filenames in the order of log rotation
func sortLogFilenames(filenames []string) {
	sort.Slice(filenames, func(i, j int) bool {
		// e.g. elastic-agent-20230515.ndjson => ["elastic-agent-20230515-1.ndjson", "20230515", "-1"]
		iGroups := logFilePattern.FindStringSubmatch(filenames[i])
		jGroups := logFilePattern.FindStringSubmatch(filenames[j])

		switch {

		// e.g. elastic-agent-20230515-1.ndjson vs elastic-agent-20230515-2.ndjson
		case iGroups[2] == jGroups[2] && iGroups[3] != "" && jGroups[3] != "":
			return iGroups[3] < jGroups[3]

		// e.g. elastic-agent-20230515.ndjson vs elastic-agent-20230515-1.ndjson
		case iGroups[2] == jGroups[2] && iGroups[3] != "":
			return false

		// e.g. elastic-agent-20230515-1.ndjson vs elastic-agent-20230515.ndjson
		case iGroups[2] == jGroups[2] && jGroups[3] != "":
			return true

		// e.g. elastic-agent-20230515.ndjson vs elastic-agent-20230516.ndjson
		default:
			return iGroups[2] < jGroups[2]
		}
	})
}

// watchLogsDir watches the log directory `dir` for new log lines, starting with the given `startFile` at
// its `startOffset` printing all new content to `w` until the `ctx` is cancelled.
// Once new log lines are written to `startFile` they are printed to `w`.
// Once a new log file is created it switches to watching the new file instead.
// The new state is checked every `watchInterval`.
func watchLogsDir(ctx context.Context, dir, startFile string, startOffset int64, w io.Writer) (err error) {
	curFile := startFile
	curOffset := startOffset

	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("watching %s interrupted: %w", startFile, ctx.Err())
		case <-ticker.C:
			size, err := getFileSize(curFile)
			if err != nil {
				return fmt.Errorf("failed to watch the logs dir %q: %w", dir, err)
			}
			if curOffset != size {
				curOffset, err = tailFile(curFile, curOffset, w)
				if err != nil {
					return fmt.Errorf("failed to watch the logs dir %q: %w", dir, err)
				}
			}

			files, err := getLogFilenames(dir)
			if err != nil {
				return fmt.Errorf("failed to watch the logs dir %q: %w", dir, err)
			}

			i := len(files) - 1
			for ; i >= 0; i-- {
				if files[i] == curFile {
					break
				}
			}
			if i == len(files)-1 {
				continue
			}
			curFile = files[i+1]
			curOffset = 0
		}
	}
}

// getFileSize returns a file size of the given file.
func getFileSize(file string) (int64, error) {
	info, err := os.Stat(file)
	if err != nil {
		return 0, fmt.Errorf("failed to stat file %q: %w", file, err)
	}
	return info.Size(), nil
}

// tailFile prints the tail of the `file` to `w` starting from `offset`.
func tailFile(file string, offset int64, w io.Writer) (size int64, err error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, fmt.Errorf("failed to open file %q: %w", file, err)
	}
	defer f.Close()

	_, err = f.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("failed to seek to %d in file %q: %w", offset, file, err)
	}

	_, err = io.Copy(w, f)
	if err != nil {
		return size, fmt.Errorf("failed to print file %s: %w", file, err)
	}

	size, err = getFileSize(file)
	if err != nil {
		return size, fmt.Errorf("failed to get file size %s: %w", file, err)
	}

	return size, nil
}
