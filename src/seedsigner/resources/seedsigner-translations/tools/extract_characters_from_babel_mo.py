"""
Extracts all unique characters that appear in the translated strings for the specified
locale.

This is a utility for build / dev purposes only.
"""

if __name__ == "__main__":
    import argparse
    import os
    from babel.messages import mofile

    # Define required input args and help text
    
    parser = argparse.ArgumentParser(
        description="Extracts all unique characters that appear in the translated strings for the specified locale."
    )
    parser.usage = "python3 extract_characters_from_babel_mo.py <locale>"
    parser.add_argument("locale", help="Target locale (e.g. es, pt_BR, zh_Hans_CN)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    debug = args.debug

    basic_chars = set((chr(c) for c in range(0x20, 0x7E + 1)))  # all basic ascii chars from SPACE to "~"

    mo_fullfilename = os.path.join(os.pardir, "l10n", args.locale, "LC_MESSAGES", "messages.mo")
    try:
        with open(mo_fullfilename, "rb") as f:
            catalog = mofile.read_mo(f)
    except FileNotFoundError:
        print(f"Could not find translations for locale \"{args.locale}\" ({mo_fullfilename})")
        exit(1)

    id_chars = set()
    translations_chars = set()
    for msg in catalog:
        if msg.id:
            if isinstance(msg.id, list):
                # plural message
                # get chars from all plural forms
                for msgid in msg.id:
                    id_chars.update(msgid)
            else:
                # singular message
                id_chars.update(msg.id)
        if msg.string:
            if isinstance(msg.string, list):
                # plural message
                # get chars from all plural forms
                for msgstring in msg.string:
                    translations_chars.update(msgstring)
            else:
                # singular message
                translations_chars.update(msg.string)

    if debug:
        # Print the difference between the chars in the ids vs the basic_chars
        print("Chars in ids but not in basic_chars:", sorted(set("".join(id_chars)) - set(basic_chars)))

        # And show the opposite
        print("Chars in basic_chars but not in ids:", sorted(basic_chars - set("".join(id_chars))))

        print("Chars in translations:", "".join(sorted(translations_chars)))

    # get a unique list of chars from all translation messages and included_chars string
    chars = sorted(translations_chars.union(basic_chars))
    
    # convert set to string
    chars_string = "".join(chars)

    # remove newlines
    chars_string = chars_string.replace("\n", "").replace("\r", "")

    print(chars_string)
