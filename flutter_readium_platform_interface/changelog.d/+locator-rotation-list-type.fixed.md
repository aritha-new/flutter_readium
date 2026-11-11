**Fixed EPUB rotation failing for locators without an ID fragment.**

Text locator conversion now preserves the required string-list type when clearing fragments, preventing a runtime cast exception during orientation realignment.
