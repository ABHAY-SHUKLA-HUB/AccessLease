const { describe, test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

describe('Unit: Resource Catalogue UI Verification', () => {
    const htmlPath = path.resolve(__dirname, '../../../frontend/index.html');
    const catalogJsPath = path.resolve(__dirname, '../../../frontend/assets/js/catalog.js');
    const htmlContent = fs.readFileSync(htmlPath, 'utf8');

    test('1. Static HTML: Navigation link has Active badge and NO Upcoming or disabled status', () => {
        assert.ok(htmlContent.includes('id="nav-link-catalog"'), 'Must have id="nav-link-catalog"');
        assert.ok(!htmlContent.includes('nav-link-disabled" data-view="view-catalog"'), 'Catalogue nav link must not have nav-link-disabled');
        assert.ok(htmlContent.includes('data-view="view-catalog"'), 'Must have data-view="view-catalog"');

        // Check badge inside catalog nav link
        const navIndex = htmlContent.indexOf('id="nav-link-catalog"');
        const navEnd = htmlContent.indexOf('</a>', navIndex);
        const navBlock = htmlContent.substring(navIndex, navEnd);
        assert.ok(navBlock.includes('nav-badge-active'), 'Nav link must have nav-badge-active');
        assert.ok(!navBlock.includes('nav-badge-upcoming'), 'Nav link must NOT have nav-badge-upcoming');
    });

    test('2. Static HTML: Dashboard Card 9 has Active badge and Open Catalogue action button', () => {
        const cardIndex = htmlContent.indexOf('<!-- Card 9: Resource Catalogue -->');
        assert.ok(cardIndex !== -1, 'Must contain Card 9: Resource Catalogue');
        const cardEnd = htmlContent.indexOf('</article>', cardIndex);
        const cardBlock = htmlContent.substring(cardIndex, cardEnd);

        assert.ok(!cardBlock.includes('module-card-disabled'), 'Card 9 must not be disabled');
        assert.ok(cardBlock.includes('nav-badge-active'), 'Card 9 must have nav-badge-active');
        assert.ok(!cardBlock.includes('nav-badge-upcoming'), 'Card 9 must NOT have nav-badge-upcoming');
        assert.ok(cardBlock.includes('data-navigate="view-catalog"'), 'Card 9 must have data-navigate="view-catalog" button');
    });

    test('3. Static HTML: #view-catalog contains functional catalogue table, filters, and modal containers', () => {
        assert.ok(htmlContent.includes('id="view-catalog"'), 'Must contain #view-catalog');
        assert.ok(htmlContent.includes('id="catalog-table"'), 'Must contain #catalog-table');
        assert.ok(htmlContent.includes('id="catalog-search-input"'), 'Must contain search input');
        assert.ok(htmlContent.includes('id="catalog-type-filter"'), 'Must contain type filter');
        assert.ok(htmlContent.includes('id="catalog-risk-filter"'), 'Must contain risk filter');
        assert.ok(htmlContent.includes('id="catalog-status-filter"'), 'Must contain status filter');
        assert.ok(htmlContent.includes('id="btn-open-create-resource-modal"'), 'Must contain register button');
        assert.ok(htmlContent.includes('id="catalog-modal-container"'), 'Must contain modal container');
        assert.ok(htmlContent.includes('id="catalog-submodal-container"'), 'Must contain submodal container');
    });

    test('4. Static HTML: Script tags include catalog.js in index.html', () => {
        assert.ok(htmlContent.includes('<script src="assets/js/catalog.js"></script>'), 'Must include catalog.js script tag');
    });

    test('5. catalog.js exists and exports AccessLeaseCatalogModule and AccessLeaseCatalog singleton', () => {
        assert.ok(fs.existsSync(catalogJsPath), 'catalog.js must exist on disk');
        const jsContent = fs.readFileSync(catalogJsPath, 'utf8');
        assert.ok(jsContent.includes('window.AccessLeaseCatalogModule = CatalogModule'), 'Must export CatalogModule class');
        assert.ok(jsContent.includes('window.AccessLeaseCatalog = new CatalogModule()'), 'Must export singleton instance');
    });
});
