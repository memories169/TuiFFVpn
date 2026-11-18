# Bundled fonts

This directory contains DejaVu Sans and DejaVu Sans Bold, embedded into
the fxvpn-desktop binary so the UI renders text on every platform —
including systems with no installed fonts (a bare Wine prefix is the
reproducible case) — and with full Vietnamese diacritic coverage
(ả ạ ế ữ ơ ư …), which the default Go font collection lacks.

- Source: <https://dejavu-fonts.github.io/> (as packaged by Debian's
  `fonts-dejavu-core` 2.37-8)
- Files: `DejaVuSans.ttf`, `DejaVuSans-Bold.ttf`

## License

The DejaVu fonts are based on Bitstream Vera and carry the
"Bitstream Vera license" (a free, permissive font license); DejaVu's own
changes are dedicated to the public domain. The full upstream license
text ships in the Debian package as
`/usr/share/doc/fonts-dejavu-core/copyright` and is reproduced here as
required by its notice clause:

> Permission is hereby granted, free of charge, to any person obtaining
> a copy of the fonts accompanying this license ("Fonts") and associated
> documentation files (the "Font Software"), to reproduce and distribute
> the Font Software, including without limitation the rights to use,
> copy, merge, publish, distribute, and/or sell copies of the Font
> Software, and to permit persons to whom the Font Software is furnished
> to do so, subject to the following conditions:
>
> The above copyright and trademark notices and this permission notice
> shall be included in all copies of one or more of the Font Software
> typefaces.
>
> The Font Software may be modified, altered, or added to, and in
> particular the designs of glyphs or characters in the Fonts may be
> modified and additional glyphs or characters may be added to the
> Fonts, only if the fonts are renamed to names not containing either
> the words "Bitstream" or the word "Vera".
>
> This License becomes null and void to the extent applicable to Fonts
> or Font Software that has been modified and is distributed under the
> "Bitstream Vera" names.
>
> The Font Software may be sold as part of a larger software package but
> no copy of one or more of the Font Software typefaces may be sold by
> itself.

Copyright (c) 2003 by Bitstream, Inc. All Rights Reserved. Bitstream
Vera is a trademark of Bitstream, Inc. DejaVu changes are in public
domain. The fonts are used unmodified; the binary embeds them as
"DejaVu Sans" / "DejaVu Sans Bold".
