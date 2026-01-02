#!/bin/bash

# Common functions for BFB build scripts

#
# Function: download_files_by_pattern
# Description: Downloads files from a URL that match a specific pattern
# Parameters:
#   $1 - base_url: The URL to fetch the listing from
#   $2 - pattern: The regex pattern to match files against
#   $3 - target_dir (optional): Target directory for downloads (default: current directory)
# Returns: 0 on success, 1 on error
#
download_files_by_pattern() {
    local base_url="$1"
    local pattern="$2"
    local target_dir="${3:-.}"
    local listing_file="listing.html"
    
    # Validate required parameters
    if [[ -z "$base_url" || -z "$pattern" ]]; then
        echo "Error: download_files_by_pattern requires base_url and pattern parameters" >&2
        echo "Usage: download_files_by_pattern <base_url> <pattern> [target_dir]" >&2
        return 1
    fi
    
    # Create target directory if it doesn't exist
    if [[ "$target_dir" != "." ]]; then
        mkdir -p "$target_dir"
    fi
    
    echo "Downloading files matching pattern '$pattern' from $base_url..."
    
    # Download the directory listing
    if ! wget -q -O "$listing_file" "$base_url/"; then
        echo "Error: Failed to download listing from $base_url" >&2
        return 1
    fi
    
    # Find the single file matching the pattern
    local filename
    filename=$(grep -oP '(?<=href=")[^"]*' "$listing_file" | grep -E "$pattern" | head -1)
    
    # Clean up listing file immediately
    rm -f "$listing_file"
    
    if [[ -n "$filename" ]]; then
        echo "Downloading: $filename"
        if wget -q -P "$target_dir" "${base_url}/${filename}"; then
            echo "Successfully downloaded $filename"
            return 0
        else
            echo "Error: Failed to download $filename" >&2
            return 1
        fi
    else
        echo "Error: No file found matching pattern '$pattern'" >&2
        return 1
    fi
}
